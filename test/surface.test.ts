// The byte-identity gate (REARCH R12): the golden documents the
// Worker embeds are exactly the committed repo goldens, the union
// document is served verbatim, every module prefix answers, and the
// discovery document carries every module's entries.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { MODULES, VERSION, discoveryDocument, handle, coreDigest, useCore } from "../src/estate";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { TrustDO } from "../src/trust-do";
import { ArchiveDO } from "../src/archive-do";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDENS = path.join(HERE, "..", "goldens");

const golden = (name: string) => readFileSync(path.join(GOLDENS, name), "utf8");

// The same pure module the worker mounts, instantiated from bytes.
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const exports = instance.exports as unknown as CoreExports;
useCore(exports);
useWorkerCore(exports);

const serve = async (path: string): Promise<Response> =>
  handle(new Request(`https://unidpp.workers.dev${path}`), env);

// The trust and archive health surfaces ride their Durable Objects —
// the same real classes the parity suites drive, bound the way the
// deployment binds them.
const fakeStorage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};
const namespaceFor = (instance: { fetch: (r: Request) => Promise<Response> }) => ({
  idFromName: (name: string) => ({ toString: () => name }),
  get: () => ({ fetch: (r: Request) => instance.fetch(r) }),
});
const env = {
  TRUST: namespaceFor(new TrustDO(fakeStorage() as never, {})),
  ARCHIVE: namespaceFor(new ArchiveDO(fakeStorage() as never, {})),
};

describe("the union surface", () => {
  it("serves the union document byte-identically", async () => {
    const response = await serve("/openapi.yaml");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(golden("union-golden.yaml"));
  });

  it("answers the deployment's own surface", async () => {
    expect((await serve("/healthz")).status).toBe(200);
    const version = (await (await serve("/version")).json()) as Record<string, string>;
    expect(version.service).toBe("unidpp");
    expect(version.runtime).toBe("cloudflare-workers");
    expect(version.version).toBe(VERSION);
    const discovery = (await (await serve("/")).json()) as {
      service: string;
      modules: { name: string; contract: string }[];
    };
    expect(discovery.service).toBe("unidpp");
    expect(discovery.modules).toHaveLength(MODULES.length);
    for (const [index, [name]] of MODULES.entries()) {
      expect(discovery.modules[index].name).toBe(name);
      expect(discovery.modules[index].contract).toBe(`/${name}/openapi.yaml`);
    }
    expect(discoveryDocument().service).toBe("unidpp");
  });

  for (const [name, source, golden_text] of MODULES) {
    it(`serves ${name} byte-identically (${source})`, async () => {
      expect(golden_text.length).toBeGreaterThan(0);
      const yaml = await serve(`/${name}/openapi.yaml`);
      expect(yaml.status).toBe(200);
      expect(await yaml.text()).toBe(golden_text);
      expect((await serve(`/${name}/healthz`)).status).toBe(200);
    });
  }

  it("renders each module's health in its native's form", async () => {
    // The parity doctrine: the edge renders what the native module
    // renders. The gateway, issuer, registry and projector answer
    // plain `ok` text/plain stamped; the log omits the stamp; the
    // resolver answers bare; identity stamps its JSON status; the hub
    // answers pretty; trust and archive ride their DOs (pinned in
    // their own suites).
    const stampedPlain = async (name: string) => {
      const r = await serve(`/${name}/healthz`);
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type")).toBe("text/plain");
      expect(r.headers.get("x-as-of")).toBeTruthy();
      expect(await r.text()).toBe("ok");
    };
    for (const name of ["registry", "issuer", "views", "render"]) {
      await stampedPlain(name);
    }
    const log = await serve("/log/healthz");
    expect(log.headers.get("content-type")).toBe("text/plain");
    expect(log.headers.get("x-as-of")).toBeNull();
    expect(await log.text()).toBe("ok");
    const resolver = await serve("/resolver/healthz");
    // The native resolver answers bare `ok` with no headers at all;
    // the Workers runtime always attaches a text content-type on a
    // string body, so the header is the platform's, the bytes are
    // the native's.
    expect(await resolver.text()).toBe("ok");
    const identity = await serve("/identity/healthz");
    expect(identity.headers.get("x-as-of")).toBeTruthy();
    expect(await identity.json()).toEqual({ status: "ok" });
    const relay = await serve("/relay/healthz");
    expect(relay.headers.get("x-as-of")).toBeTruthy();
    expect(await relay.text()).toBe('{\n  "status": "ok"\n}');

    // Trust: the DO's signed healthz — the native fields, the trust
    // signature posture.
    const trust = await serve("/trust/healthz");
    expect(trust.status).toBe(200);
    expect(trust.headers.get("x-sig-domain")).toBe("tree-head");
    const trustBody = (await trust.json()) as {
      status?: string;
      service?: string;
      as_of?: string;
    };
    expect(trustBody.status).toBe("ok");
    expect(trustBody.service).toBe("unidpp-trust");
    expect(trustBody.as_of).toBeTruthy();

    // Archive: the DO's counted healthz — the native fields with the
    // store's snapshot count and the anchoring posture.
    const archive = await serve("/archive/healthz");
    expect(archive.status).toBe(200);
    expect(archive.headers.get("x-as-of")).toBeTruthy();
    const archiveBody = (await archive.json()) as {
      status?: string;
      service?: string;
      snapshots?: number;
      anchoring_enabled?: boolean;
      as_of?: string;
    };
    expect(archiveBody.status).toBe("ok");
    expect(archiveBody.service).toBe("unidpp-archive");
    expect(archiveBody.snapshots).toBe(0);
    expect(archiveBody.anchoring_enabled).toBe(false);
    expect(archiveBody.as_of).toBeTruthy();
  });

  it("refuses unknown paths with the stated 404", async () => {
    const response = await serve("/nope");
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "no such path" });
  });

  it("digests through the wasm core like the model crate", () => {
    expect(coreDigest(new TextEncoder().encode(""))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
