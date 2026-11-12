// The rule-expression language's estate gates (R10 G4): the same
// grammar and semantics the native chain carries — the descriptor's
// expressions validate at intake (parse, declared paths, literal
// kinds, resolved references), the instance intake evaluates every
// referenced rule and names the failing rule, and the workbench
// evaluates rules against worked instances.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { RegistryDO } from "../src/registry-do";
import { evalRule, parseRule } from "../src/rules";

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

const RULE = "tyre.pressure-bar >= 1.0 and tyre.pressure-bar <= 4.5";

const registerDescriptor = async (
  registry: RegistryDO,
  overrides: Record<string, unknown> = {},
  classId = "tyre-e8",
): Promise<Response> =>
  serve(registry, "/items", {
    method: "POST",
    body: JSON.stringify({
      register_id: "unidpp-registry",
      item_id: classId,
      class: "class-descriptor",
      definition: `The ${classId} class`,
      version: "1.0.0",
      manifest: {
        version: "1.0.0",
        class_id: classId,
        issuer_class: "consensus",
        issuer: "urn:unidpp:actor:consortium",
        signature: { signature: "dGVzdC1zaWduYXR1cmU" },
        features: [
          { path: "tyre.pressure-bar", kind: "decimal", required: true, unit: "bar" },
          { path: "tyre.season", kind: "string", required: true, vocabulary: ["summer", "winter"] },
        ],
        capability_classes: ["silent"],
        rule_references: ["rule.pressure-range"],
        rules: [{ id: "rule.pressure-range", expr: RULE }],
        ...overrides,
      },
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

describe("the rule-expression language", () => {
  it("evaluates deterministically over the same facts", () => {
    const parsed = parseRule(RULE);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const facts = { "tyre.pressure-bar": 2.3 };
    const first = evalRule(parsed.expr, facts);
    for (let i = 0; i < 5; i += 1) {
      expect(evalRule(parsed.expr, facts)).toBe(first);
    }
    expect(evalRule(parsed.expr, { "tyre.pressure-bar": 9.9 })).toBe(false);
    expect(evalRule(parsed.expr, {})).toBe(false);
    expect(evalRule(parsed.expr, { "tyre.pressure-bar": "high" })).toBe(false);
  });

  it("refuses a descriptor whose expression does not parse", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerDescriptor(registry, {
      rules: [{ id: "rule.pressure-range", expr: "tyre.pressure-bar >" }],
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("does not parse");
  });

  it("refuses a dangling rule reference", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerDescriptor(registry, { rules: [] });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("names no rule");
  });

  it("refuses an expression naming an undeclared path", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerDescriptor(registry, {
      rules: [{ id: "rule.depth", expr: "tyre.depth > 2" }],
      rule_references: ["rule.depth"],
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("tyre.depth");
    expect(body.error).toContain("does not declare");
  });

  it("refuses an ordering rule on a string feature", async () => {
    const registry = new RegistryDO(storage());
    const served = await registerDescriptor(registry, {
      rules: [{ id: "rule.season", expr: 'tyre.season > "winter"' }],
      rule_references: ["rule.season"],
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("decimal-only");
  });

  it("refuses an instance failing a referenced rule, naming the rule", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    const served = await registerInstance(registry, {
      "tyre.pressure-bar": 9.9,
      "tyre.season": "winter",
    });
    expect(served.status).toBe(400);
    const body = (await served.json()) as { error: string };
    expect(body.error).toContain("rule.pressure-range");
    expect(body.error).toContain("not satisfied");
  });

  it("registers an instance satisfying the referenced rules", async () => {
    const registry = new RegistryDO(storage());
    await registerDescriptor(registry);
    await serve(registry, "/items", {
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
    const served = await registerInstance(registry, {
      "tyre.pressure-bar": 2.3,
      "tyre.season": "winter",
    });
    expect(served.status).toBe(201);
  });
});
