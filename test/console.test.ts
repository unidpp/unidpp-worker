// The console gates (REARCH R12 S5-serve): the operator pages
// computed from the estate's own state, the strict escaping of
// operator-supplied values, the session gate closing where an admin
// token is configured and serving open where none is, and the
// restore drill riding the archive.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";
import { RegistryDO } from "../src/registry-do";
import { consoleSurface } from "../src/console";

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

const serve = (
  path: string,
  init?: RequestInit,
  env: Parameters<typeof consoleSurface>[2] = {},
): Promise<Response> =>
  consoleSurface(path, new Request(`https://console.unidpp.org/console${path}`, init), env);

describe("the console surface", () => {
  it("renders the dashboard's module cards", async () => {
    const page = await serve("/", {}, {});
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("registry");
    expect(html).toContain("healthy");
  });

  it("serves the probes ungated", async () => {
    const health = await serve("/healthz");
    expect(health.status).toBe(200);
    const identity = await serve("/.well-known/unidpp-service");
    const body = (await identity.json()) as { service: string; version: string };
    expect(body.service).toBe("unidpp");
  });

  it("lists the issuer's passports and the registry's items", async () => {
    const issuer = new IssuerDO(storage());
    const registry = new RegistryDO(storage());
    await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({ identity: "cpid:urn:test:console" }),
      }),
    );
    await registry.fetch(
      new Request("https://do.internal/items", {
        method: "POST",
        body: JSON.stringify({
          register_id: "unidpp-registry",
          item_id: "urn:test:console-item",
          class: "data-element",
          definition: "A console fixture",
          version: "1.0.0",
        }),
      }),
    );
    const passports = await serve("/passports", {}, {
      ISSUER: {
        idFromName: (n: string) => n,
        get: () => ({ fetch: issuer.fetch.bind(issuer) }),
      },
    });
    expect(passports.status).toBe(200);
    expect(await passports.text()).toContain("cpid:urn:test:console");
    const items = await serve("/registry", {}, {
      REGISTRY: {
        idFromName: (n: string) => n,
        get: () => ({ fetch: registry.fetch.bind(registry) }),
      },
    });
    expect(items.status).toBe(200);
    expect(await items.text()).toContain("urn:test:console-item");
  });

  it("escapes operator-supplied values", async () => {
    const issuer = new IssuerDO(storage());
    await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({
          identity: `cpid:urn:test:<script>alert(1)</script>`,
        }),
      }),
    );
    const passports = await serve("/passports", {}, {
      ISSUER: {
        idFromName: (n: string) => n,
        get: () => ({ fetch: issuer.fetch.bind(issuer) }),
      },
    });
    const html = await passports.text();
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("serves open until the admin token is configured", async () => {
    const open = await serve("/config", {}, { UNIDPP_CONSOLE_ADMIN_TOKEN: undefined });
    expect(open.status).toBe(200);
    const gated = await serve("/config", {}, { UNIDPP_CONSOLE_ADMIN_TOKEN: "console-secret" });
    expect(gated.status).toBe(303);
    expect(gated.headers.get("location")).toBe("/console/login");
    const login = await serve("/login", {}, { UNIDPP_CONSOLE_ADMIN_TOKEN: "console-secret" });
    expect(login.status).toBe(200);
    const refused = await serve("/login", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "token=wrong",
    }, {
      UNIDPP_CONSOLE_ADMIN_TOKEN: "console-secret",
    });
    expect(await refused.text()).toContain("refused");
    const accepted = await serve(
      "/login",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "token=console-secret",
      },
      { UNIDPP_CONSOLE_ADMIN_TOKEN: "console-secret" },
    );
    expect(accepted.status).toBe(303);
    const cookie = accepted.headers.get("set-cookie") ?? "";
    expect(cookie).toContain("unidpp-console=");
    expect(cookie).not.toContain("console-secret");
    const withSession = await serve("/config", {
      headers: { cookie: cookie.split(";")[0] },
    }, { UNIDPP_CONSOLE_ADMIN_TOKEN: "console-secret" });
    expect(withSession.status).toBe(200);
  });

  it("renders the tenants from the host map", async () => {
    const page = await serve("/tenants", {}, {
      TENANT_HOSTS: JSON.stringify({ "dpp.acme.example.org": "acme" }),
    });
    const html = await page.text();
    expect(html).toContain("dpp.acme.example.org");
    expect(html).toContain("acme");
  });

  it("drills a restore through the archive", async () => {
    const { ArchiveDO } = await import("../src/archive-do");
    const archive = new ArchiveDO(storage(), {});
    const drilled = await serve("/backups/drill", {
      method: "POST",
      body: new URLSearchParams({
        passport_id: "urn:test:drill",
        state_hash: "aa".repeat(32),
        log_head: "bb".repeat(32),
      }),
    }, {
      ARCHIVE: {
        idFromName: (n: string) => n,
        get: () => ({ fetch: archive.fetch.bind(archive) }),
      },
    });
    expect(drilled.status).toBe(201);
    const body = (await drilled.json()) as { snapshot_id?: string };
    expect(body.snapshot_id).toMatch(/^snap-/);
  });
});
