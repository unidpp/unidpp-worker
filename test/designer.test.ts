// The class designer's gates (R10 G1): the draft validates against
// the same checks intake runs, worked instances conform or refuse
// with the failing fact path named, and sign-and-submit registers a
// REAL signature into the estate's own register (surfaced by
// discovery), under the console's session gate.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { RegistryDO } from "../src/registry-do";
import { designer } from "../src/designer";

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

const FEATURES = JSON.stringify([
  { path: "tyre.pressure-bar", kind: "decimal", required: true, unit: "bar" },
  { path: "tyre.season", kind: "string", required: true, vocabulary: ["summer", "winter"] },
  { path: "tyre.runflat", kind: "boolean", required: false },
]);

const formBody = (overrides: Record<string, string> = {}): URLSearchParams =>
  new URLSearchParams({
    class_id: "tyre-e8",
    definition: "The E8 tyre class",
    version: "1.0.0",
    issuer_class: "consensus",
    issuer: "urn:unidpp:actor:consortium",
    capability_classes: "silent, logged-contact",
    rule_references: "rule.pressure-range",
    features: FEATURES,
    instances: JSON.stringify([
      { "tyre.pressure-bar": 2.3, "tyre.season": "winter", "tyre.runflat": true },
    ]),
    action: "validate",
    ...overrides,
  });

const post = (body: URLSearchParams, env: Parameters<typeof designer>[1] = {}): Promise<Response> =>
  designer(
    new Request("https://console.unidpp.org/console/designer", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }),
    env,
  );

const registryEnv = (registry: RegistryDO): Parameters<typeof designer>[1] => ({
  REGISTRY: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: registry.fetch.bind(registry) }),
  },
});

describe("the class designer", () => {
  it("serves the authoring form", async () => {
    const page = await designer(new Request("https://console.unidpp.org/console/designer"), {});
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("class_id");
    expect(html).toContain("validate the draft");
    expect(html).toContain("sign and submit");
  });

  it("validates a conforming draft and its worked instance", async () => {
    const page = await post(formBody());
    const html = await page.text();
    expect(html).toContain("well-shaped manifest");
    expect(html).toContain("conforms to the draft");
  });

  it("names the failing fact path on a nonconforming worked instance", async () => {
    const page = await post(
      formBody({
        instances: JSON.stringify([{ "tyre.season": "competitive" }]),
      }),
    );
    const html = await page.text();
    expect(html).toContain("tyre.pressure-bar");
    expect(html).toContain("missing-required");
    expect(html).toContain("out-of-vocabulary");
  });

  it("names the draft's own shape failures", async () => {
    const page = await post(
      formBody({
        issuer: "",
        features: JSON.stringify([{ path: "x", kind: "polygon", required: false }]),
      }),
    );
    const html = await page.text();
    expect(html).toContain("not a value kind");
    expect(html).toContain("manifest.issuer");
  });

  it("signs and submits into the register, and discovery surfaces it", async () => {
    const registry = new RegistryDO(storage());
    const page = await post(formBody({ action: "submit" }), registryEnv(registry));
    const html = await page.text();
    expect(html).toContain("is registered (signed by ");
    const discovery = await registry.fetch(new Request("https://do.internal/discovery"));
    const body = (await discovery.json()) as {
      class_descriptors: { class_id: string; features: unknown[] }[];
    };
    expect(body.class_descriptors).toHaveLength(1);
    expect(body.class_descriptors[0].class_id).toBe("tyre-e8");
    // The registered manifest carries the real signature block.
    const item = (await (
      await registry.fetch(new Request("https://do.internal/items/tyre-e8"))
    ).json()) as { manifest?: { signature?: { signature?: string; key_id?: string } } };
    expect(item.manifest?.signature?.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(item.manifest?.signature?.key_id).toBeTruthy();
  });

  it("relays the register's refusal, naming the paths", async () => {
    const registry = new RegistryDO(storage());
    // An empty signature slot: the console signs the canonical body,
    // but the draft itself refuses (the signature slot the designer
    // assembles fills it — so break the shape instead: a bad kind).
    const page = await post(
      formBody({
        action: "submit",
        features: JSON.stringify([{ path: "tyre.x", kind: "polygon", required: false }]),
      }),
      registryEnv(registry),
    );
    const html = await page.text();
    expect(html).toContain("not a value kind");
    const discovery = await registry.fetch(new Request("https://do.internal/discovery"));
    const body = (await discovery.json()) as { class_descriptors: unknown[] };
    expect(body.class_descriptors).toHaveLength(0);
  });

  it("the registered signature verifies through the boundary", async () => {
    const registry = new RegistryDO(storage());
    await post(formBody({ action: "submit" }), registryEnv(registry));
    const item = (await (
      await registry.fetch(new Request("https://do.internal/items/tyre-e8"))
    ).json()) as {
      manifest?: { signature?: { signature?: string } };
    };
    const registered = item.manifest?.signature?.signature ?? "";
    // The canonical body the console signed: the manifest without the
    // signature slot, stable-key serialized.
    const manifest = JSON.parse(
      JSON.stringify({
        version: "1.0.0",
        class_id: "tyre-e8",
        issuer_class: "consensus",
        issuer: "urn:unidpp:actor:consortium",
        features: JSON.parse(FEATURES),
        capability_classes: ["silent", "logged-contact"],
        rule_references: ["rule.pressure-range"],
      }),
    ) as Record<string, unknown>;
    const stable = (value: unknown): string => {
      if (value === null || typeof value !== "object") return JSON.stringify(value);
      if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
      const keys = Object.keys(value as Record<string, unknown>).sort();
      return `{${keys
        .map((k) => `${JSON.stringify(k)}:${stable((value as Record<string, unknown>)[k])}`)
        .join(",")}}`;
    };
    const body = new TextEncoder().encode(stable(manifest));
    const label = new TextEncoder().encode("UNIDPP-CONSOLE/DESIGNER-SEED");
    const labelPtr = core.unidpp_alloc(label.length);
    new Uint8Array(core.memory.buffer, labelPtr, label.length).set(label);
    const seedPtr = core.unidpp_alloc(32);
    core.unidpp_sha256(labelPtr, label.length, seedPtr);
    const bodyPtr = core.unidpp_alloc(body.length);
    new Uint8Array(core.memory.buffer, bodyPtr, body.length).set(body);
    const domain = new TextEncoder().encode("profile");
    const domainPtr = core.unidpp_alloc(domain.length);
    new Uint8Array(core.memory.buffer, domainPtr, domain.length).set(domain);
    const sigPtr = core.unidpp_alloc(64);
    expect(
      core.unidpp_sign_raw(seedPtr, domainPtr, domain.length, bodyPtr, body.length, sigPtr),
    ).toBe(0);
    const expected = Array.from(new Uint8Array(core.memory.buffer, sigPtr, 64).slice())
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(registered).toBe(expected);
  });
});
