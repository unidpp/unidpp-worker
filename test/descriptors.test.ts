// The R10 estate gates (clause 5): the class descriptor registers
// only in its signed, well-shaped form; the instance intake resolves
// the descriptor point-in-time and refuses missing-required,
// wrong-kind, out-of-vocabulary, unresolved-unit and unknown-class,
// naming the failing fact path; discovery surfaces the descriptors.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { RegistryDO } from "../src/registry-do";
import { handle } from "../src/estate";

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

const serve = (registry: RegistryDO, path: string, init?: RequestInit): Promise<Response> =>
  registry.fetch(new Request(`https://do.internal${path}`, init));

const descriptorManifest = (classId: string) => ({
  version: "1.0.0",
  class_id: classId,
  issuer_class: "consensus",
  issuer: "urn:unidpp:actor:consortium",
  signature: { signature: "dGVzdC1zaWduYXR1cmU" },
  features: [
    { path: "tyre.pressure-bar", kind: "decimal", required: true, unit: "bar" },
    { path: "tyre.season", kind: "string", required: true, vocabulary: ["summer", "winter", "all-season"] },
    { path: "tyre.runflat", kind: "boolean", required: false },
    { path: "tyre.sizes", kind: "list", required: false },
  ],
  capability_classes: ["silent", "logged-contact"],
  rule_references: ["rule.pressure-range"],
});

const registerDescriptor = async (registry: RegistryDO, classId = "tyre-e8"): Promise<Response> =>
  serve(registry, "/items", {
    method: "POST",
    body: JSON.stringify({
      register_id: "unidpp-registry",
      item_id: classId,
      class: "class-descriptor",
      definition: `The ${classId} class`,
      version: "1.0.0",
      manifest: descriptorManifest(classId),
    }),
  });

const registerUnit = async (registry: RegistryDO): Promise<Response> =>
  serve(registry, "/items", {
    method: "POST",
    body: JSON.stringify({
      register_id: "unidpp-registry",
      item_id: "bar",
      class: "unit",
      definition: "The pressure unit bar",
      version: "1.0.0",
      manifest: { version: "1.0.0", name: "bar", symbol: "bar" },
    }),
  });

const registerInstance = async (
  registry: RegistryDO,
  features: Record<string, unknown>,
  classId = "tyre-e8",
): Promise<Response> =>
  serve(registry, "/items", {
    method: "POST",
    body: JSON.stringify({
      register_id: "unidpp-registry",
      item_id: "instance-tyre-0001",
      class: "instance",
      definition: "A tyre instance",
      version: "1.0.0",
      manifest: { version: "1.0.0", instance_of: classId, features },
    }),
  });

describe("the class descriptor intake", () => {
  it("registers a signed, well-shaped descriptor", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerDescriptor(registry);
    expect(served.status).toBe(201);
    const discovery = await serve(registry, "/discovery");
    const body = (await discovery.json()) as {
      class_descriptors: {
        class_id: string;
        features: { path: string; kind: string; unit: string | null }[];
      }[];
    };
    expect(body.class_descriptors).toHaveLength(1);
    expect(body.class_descriptors[0].class_id).toBe("tyre-e8");
    expect(body.class_descriptors[0].features).toHaveLength(4);
    expect(body.class_descriptors[0].features[0].unit).toBe("bar");
  });

  it("refuses an unsigned descriptor", async () => {
    const registry = new RegistryDO(storage());
    const manifest = descriptorManifest("tyre-e8");
    (manifest.signature as Record<string, unknown>).signature = "";
    const served = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: "tyre-e8",
        class: "class-descriptor",
        definition: "The tyre class",
        version: "1.0.0",
        manifest,
      }),
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("manifest.signature");
  });

  it("refuses a class_id that does not name the item", async () => {
    const registry = new RegistryDO(storage());
    const served = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: "tyre-e8",
        class: "class-descriptor",
        definition: "The tyre class",
        version: "1.0.0",
        manifest: descriptorManifest("some-other-class"),
      }),
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("class_id");
  });

  it("refuses a fifth value kind", async () => {
    const registry = new RegistryDO(storage());
    const manifest = descriptorManifest("tyre-e8");
    manifest.features = [
      { path: "tyre.geometry", kind: "polygon", required: false },
    ];
    const served = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: "tyre-e8",
        class: "class-descriptor",
        definition: "The tyre class",
        version: "1.0.0",
        manifest,
      }),
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("is not a value kind");
  });
});

describe("the estate routes the registry's discovery", () => {
  it("serves /registry/discovery through the estate", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    const response = await handle(new Request("https://unidpp.workers.dev/registry/discovery"), {
      REGISTRY: {
        idFromName: (n: string) => n,
        get: () => ({ fetch: registry.fetch.bind(registry) }),
      },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { class_descriptors: { class_id: string }[] };
    expect(body.class_descriptors).toHaveLength(1);
    expect(body.class_descriptors[0].class_id).toBe("tyre-e8");
  });
});

describe("the instance intake", () => {
  const conforming = () => ({
    "tyre.pressure-bar": 2.3,
    "tyre.season": "winter",
    "tyre.runflat": true,
    "tyre.sizes": ["205/55R16"],
    "tyre.open-fact": "rides unvalidated (the open map)",
  });

  it("registers a conforming instance", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await registerUnit(registry);
    const served = await registerInstance(registry, conforming());
    expect(served.status).toBe(201);
  });

  it("refuses a missing required fact (IC1)", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await registerUnit(registry);
    const features = { "tyre.season": "winter" };
    const served = await registerInstance(registry, features);
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("tyre.pressure-bar");
    expect(body.error).toContain("missing-required");
  });

  it("refuses a wrong kind (IC2)", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await registerUnit(registry);
    const served = await registerInstance(registry, {
      "tyre.pressure-bar": 2.3,
      "tyre.season": true,
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("tyre.season");
    expect(body.error).toContain("wrong-kind");
  });

  it("refuses an out-of-vocabulary member (IC3)", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await registerUnit(registry);
    const served = await registerInstance(registry, {
      "tyre.pressure-bar": 2.3,
      "tyre.season": "competitive",
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("out-of-vocabulary");
  });

  it("refuses an unresolved unit (IC4)", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    const served = await registerInstance(registry, conforming());
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("unresolved-unit");
    expect(body.error).toContain("bar");
  });

  it("refuses an unknown class (IC5)", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerInstance(registry, { x: 1 }, "no-such-class");
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("unknown class");
  });

  it("gates a superseding instance manifest through the same checks", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await registerUnit(registry);
    await registerInstance(registry, conforming());
    const superseded = await serve(registry, "/items/instance-tyre-0001/versions", {
      method: "POST",
      body: JSON.stringify({
        version: "1.1.0",
        reason: "a wrong-kind correction attempt",
        manifest: {
          version: "1.1.0",
          instance_of: "tyre-e8",
          features: { "tyre.season": true },
        },
      }),
    });
    expect(superseded.status).toBe(400);
    const body = (await superseded.json()) as { error: string };
    expect(body.error).toContain("wrong-kind");
  });
});
