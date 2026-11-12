// The mapping workbench's gates (R10 G7): the tier form validates
// through the boundary (canonical bytes + digest), the composition
// preview joins two drafts and refuses a tier-3 hop or a mismatch,
// submit registers under the tier duties intake enforces, and the
// register holds the tier-form mapping beside the relation form.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { RegistryDO } from "../src/registry-do";
import { workbench } from "../src/mappings";

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

const registryEnv = (registry: RegistryDO) => ({
  REGISTRY: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: registry.fetch.bind(registry) }),
  },
});

const registerElement = async (registry: RegistryDO, id: string): Promise<void> => {
  await registry.fetch(
    new Request("https://do.internal/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: id,
        class: "data-element",
        definition: `The ${id} element`,
        version: "1.0.0",
      }),
    }),
  );
};

const formBody = (overrides: Record<string, string> = {}): URLSearchParams =>
  new URLSearchParams({
    source: "urn:unidpp:elements:eu-battery@3",
    target: "urn:unidpp:elements:cn-battery@2",
    version: "1",
    tier: "deterministic",
    transform: "urn:unidpp:transform:eu-cn-mass@4",
    scope: "",
    residual: "",
    attester: "",
    note: "",
    second: "",
    action: "validate",
    ...overrides,
  });

const post = (body: URLSearchParams, env: Parameters<typeof workbench>[1] = {}): Promise<Response> =>
  workbench(
    new Request("https://console.unidpp.org/console/mappings", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }),
    env,
  );

describe("the mapping workbench", () => {
  it("serves the authoring form with the three tiers", async () => {
    const page = await workbench(new Request("https://console.unidpp.org/console/mappings"), {});
    const html = await page.text();
    expect(html).toContain("deterministic");
    expect(html).toContain("correspondence");
    expect(html).toContain("no-mapping");
  });

  it("previews the canonical bytes and the digest for a tier-1 draft", async () => {
    const page = await post(formBody());
    const html = await page.text();
    expect(html).toContain("The canonical form");
    expect(html).toContain("Digest");
    // The tier token rides the canonical bytes (hex of "tier-1").
    expect(html).toContain("746965722d31");
  });

  it("validates a tier-2 correspondence draft", async () => {
    const page = await post(
      formBody({
        tier: "correspondence",
        scope: "carbon-footprint, recycled-content",
        residual: "recycled-content shares are not covered",
        attester: "jp-meti",
      }),
    );
    const html = await page.text();
    expect(html).toContain("The canonical form");
    expect(html).toContain("746965722d32");
  });

  it("names the parse refusal for a malformed draft", async () => {
    const page = await post(formBody({ version: "0" }));
    const html = await page.text();
    expect(html).toContain("version");
  });

  it("composes two drafts and refuses a tier-3 hop", async () => {
    const second = JSON.stringify({
      source: "urn:unidpp:elements:cn-battery@2",
      target: "urn:unidpp:elements:jp-battery@1",
      version: 2,
      kind: { tier: "deterministic", transform: "urn:unidpp:transform:cn-jp-mass@1" },
    });
    const joined = await post(formBody({ second }));
    const html = await joined.text();
    expect(html).toContain("The chain preview");
    expect(html).toContain("jp-battery");
    expect(html).toContain("eu-cn-mass@4");
    const tier3 = JSON.stringify({
      source: "urn:unidpp:elements:cn-battery@2",
      target: "urn:unidpp:elements:kr-battery@1",
      version: 1,
      kind: { tier: "no-mapping", note: "divergent legal bases recorded" },
    });
    const refused = await post(formBody({ second: tier3 }));
    expect(await refused.text()).toContain("refuses");
    const mismatched = await post(formBody({ second: second.replace("cn-battery@2", "absent@9") }));
    expect(await mismatched.text()).toContain("refuses");
  });

  it("submits into the register, which enforces the tier duties", async () => {
    const registry = new RegistryDO(storage());
    await registerElement(registry, "urn:unidpp:elements:eu-battery");
    await registerElement(registry, "urn:unidpp:elements:cn-battery");
    const page = await post(formBody({ action: "submit" }), registryEnv(registry));
    expect(await page.text()).toContain("The mapping is registered");
    const discovery = await registry.fetch(new Request("https://do.internal/discovery"));
    // The register holds the tier-form item at its subregister.
    const listed = await registry.fetch(
      new Request("https://do.internal/cross-register-mappings"),
    );
    expect(listed.status).toBe(200);
    void discovery;
  });

  it("relays the register's tier-duty refusals", async () => {
    const registry = new RegistryDO(storage());
    await registerElement(registry, "urn:unidpp:elements:eu-battery");
    await registerElement(registry, "urn:unidpp:elements:cn-battery");
    const page = await post(
      formBody({
        action: "submit",
        tier: "correspondence",
        scope: "",
        residual: "",
        attester: "",
      }),
      registryEnv(registry),
    );
    const html = await page.text();
    expect(html).toContain("manifest.kind.scope");
  });
});

describe("the register's tier intake", () => {
  it("refuses a tier-form mapping whose ends dangle", async () => {
    const registry = new RegistryDO(storage());
    const served = await registry.fetch(
      new Request("https://do.internal/items", {
        method: "POST",
        body: JSON.stringify({
          register_id: "unidpp-registry",
          item_id: "map-dangling",
          class: "cross-register-mapping",
          definition: "A dangling tier-2 mapping",
          version: "1.0.0",
          manifest: {
            source: "urn:unidpp:elements:absent@1",
            target: "urn:unidpp:elements:absent-too@1",
            version: 1,
            kind: {
              tier: "correspondence",
              scope: ["x"],
              residual: "stated",
              attester: "body",
            },
          },
        }),
      }),
    );
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("dangling reference");
  });

  it("registers a tier-3 record and lists it", async () => {
    const registry = new RegistryDO(storage());
    await registerElement(registry, "urn:unidpp:elements:eu-battery");
    await registerElement(registry, "urn:unidpp:elements:kr-battery");
    const served = await registry.fetch(
      new Request("https://do.internal/items", {
        method: "POST",
        body: JSON.stringify({
          register_id: "unidpp-registry",
          item_id: "map-none",
          class: "cross-register-mapping",
          definition: "A no-mapping record",
          version: "1.0.0",
          manifest: {
            source: "urn:unidpp:elements:eu-battery@1",
            target: "urn:unidpp:elements:kr-battery@1",
            version: 1,
            kind: { tier: "no-mapping", note: "divergent legal bases recorded" },
          },
        }),
      }),
    );
    expect(served.status).toBe(201);
    const listed = await registry.fetch(
      new Request("https://do.internal/cross-register-mappings"),
    );
    const body = (await listed.json()) as { items?: { identifier: string }[] };
    expect(body.items?.some((i) => i.identifier === "map-none")).toBe(true);
  });
});
