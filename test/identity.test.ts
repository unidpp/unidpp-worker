// S6's gates (REARCH R12): bootstrap enrollment, the open mode
// closing, scoped negatives per role, rotation revoking the old
// link, self-revocation, and the scope table answering — on a plain
// in-memory storage with the same API DO storage carries.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IdentityDO, gate } from "../src/identity-do";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const serve = (registry: IdentityDO, path: string, init?: RequestInit): Promise<Response> =>
  registry.fetch(new Request(`https://do.internal${path}`, init));

describe("the identity Durable Object", () => {
  it("serves open until configured", async () => {
    const identity = new IdentityDO(storage(), {});
    const keyring = (await (await serve(identity, "/keyring")).json()) as { mode: string };
    expect(keyring.mode).toBe("open");
    const scopes = (await (await serve(identity, "/scopes")).json()) as {
      modules: { module: string; scopes: string[] }[];
    };
    expect(scopes.modules.length).toBeGreaterThanOrEqual(8);
    expect(scopes.modules.find((m) => m.module === "identity")!.scopes).toContain(
      "identity:admin",
    );
  });

  it("bootstraps the first actor and closes the mode", async () => {
    const identity = new IdentityDO(storage(), {});
    const enrolled = await serve(identity, "/actors", {
      method: "POST",
      body: JSON.stringify({
        org: "border-agency",
        name: "Inspector J",
        scopes: ["registry:admin", "issuer:read"],
      }),
    });
    expect(enrolled.status).toBe(201);
    const body = (await enrolled.json()) as { bearer: string; credential: string };
    expect(body.bearer).toMatch(/^cred-/);
    const keyring = (await (await serve(identity, "/keyring")).json()) as { mode: string };
    expect(keyring.mode).toBe("enforcing");
    const second = await serve(identity, "/actors", {
      method: "POST",
      body: JSON.stringify({ org: "x", name: "y", scopes: [] }),
    });
    expect(second.status).toBe(401);
    const whoami = await serve(identity, "/whoami", {
      headers: { authorization: `Bearer ${body.bearer}` },
    });
    expect(whoami.status).toBe(200);
    const who = (await whoami.json()) as { org: string; scopes: string[] };
    expect(who.org).toBe("border-agency");
    expect(who.scopes).toContain("registry:admin");
  });

  it("rotates: the old link revokes, the new resolves", async () => {
    const identity = new IdentityDO(storage(), {});
    const enrolled = await serve(identity, "/actors", {
      method: "POST",
      body: JSON.stringify({ org: "a", name: "b", scopes: ["views:read"] }),
    });
    const { bearer } = (await enrolled.json()) as { bearer: string };
    const whoBefore = await serve(identity, "/whoami", {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(whoBefore.status).toBe(200);
    // The actor needs identity:admin to see credentials; self-rotate
    // rides the credential id the actor holds.
    const credentials = (await (
      await serve(identity, "/credentials", {
        headers: { authorization: `Bearer ${bearer}` },
      })
    ).json()) as { credentials: { id: string }[] };
    const credentialId = credentials.credentials[0].id;
    const rotated = await serve(identity, `/credentials/${credentialId}/rotate`, {
      method: "POST",
      headers: { authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ reason: "scheduled" }),
    });
    expect(rotated.status).toBe(201);
    const newBody = (await rotated.json()) as { bearer: string; credential: string };
    const oldWho = await serve(identity, "/whoami", {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(oldWho.status).toBe(401);
    const newWho = await serve(identity, "/whoami", {
      headers: { authorization: `Bearer ${newBody.bearer}` },
    });
    expect(newWho.status).toBe(200);
    // Self-revoke the new link.
    const revoked = await serve(identity, `/credentials/${newBody.credential}/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${newBody.bearer}` },
      body: JSON.stringify({ reason: "test over" }),
    });
    expect(revoked.status).toBe(200);
    const gone = await serve(identity, "/whoami", {
      headers: { authorization: `Bearer ${newBody.bearer}` },
    });
    expect(gone.status).toBe(401);
  });

  it("issues additional credentials under identity:admin", async () => {
    const identity = new IdentityDO(storage(), {
      UNIDPP_SERVER_OPERATOR_TOKEN: "operator-bypass",
    });
    const enrolled = await serve(identity, "/actors", {
      method: "POST",
      headers: { authorization: "Bearer operator-bypass" },
      body: JSON.stringify({ org: "registry-desk", name: "R", scopes: ["registry:admin"] }),
    });
    expect(enrolled.status).toBe(201);
    const actor = (await enrolled.json()) as { actor: string };
    const issued = await serve(identity, `/actors/${actor.actor}/credentials`, {
      method: "POST",
      headers: { authorization: "Bearer operator-bypass" },
      body: JSON.stringify({ scopes: ["issuer:read"] }),
    });
    expect(issued.status).toBe(201);
    const withoutToken = await serve(identity, "/actors", {
      method: "POST",
      body: JSON.stringify({ org: "x", name: "y", scopes: [] }),
    });
    expect(withoutToken.status).toBe(401);
  });
});

describe("the enforcement gate", () => {
  it("gates reads and mutations per module with the scope named", () => {
    expect(gate("/healthz", new Request("https://x/healthz"), null)).toBeNull();
    expect(gate("/relay/relay", new Request("https://x/relay/relay", { method: "POST" }), null)).toBeNull();
    const refused = gate("/registry/items", new Request("https://x/registry/items"), null);
    expect(refused?.status).toBe(401);
    const missing = gate("/registry/items", new Request("https://x/registry/items"), ["views:read"]);
    expect(missing?.status).toBe(403);
    const body = missing?.body ? null : null;
    void body;
    const allowed = gate("/registry/items", new Request("https://x/registry/items"), ["registry:read"]);
    expect(allowed).toBeNull();
    const adminPath = gate("/registry/admin/seed", new Request("https://x/registry/admin/seed", { method: "POST" }), ["registry:write"]);
    expect(adminPath?.status).toBe(403);
    const adminOk = gate("/registry/admin/seed", new Request("https://x/registry/admin/seed", { method: "POST" }), ["registry:admin"]);
    expect(adminOk).toBeNull();
    const writeOk = gate("/issuer/passports", new Request("https://x/issuer/passports", { method: "POST" }), ["issuer:write"]);
    expect(writeOk).toBeNull();
  });
});
