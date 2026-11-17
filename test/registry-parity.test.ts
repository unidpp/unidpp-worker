// The registry's contract parity on the Durable Object (REARCH R12
// S2): the routes the estate forwards — admin log and seed, the
// supersession chains, applicability with the clock predicates, the
// discovery registry (C3 services, C4 protocol bindings, C5
// verification mechanisms), the profile-manifest schema, the EXPRESS
// model deposits, the cross-register-mapping lookup, and the
// class-generic subregister mounts — on a plain in-memory storage
// with the same API DO storage carries.

import { describe, expect, it } from "vitest";
import { RegistryDO } from "../src/registry-do";

class FakeStorage {
  private map = new Map<string, unknown>();
  async put(key: string, value: unknown): Promise<void> {
    this.map.set(key, value);
  }
  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }
  async list(options: { prefix: string }): Promise<Map<string, unknown>> {
    return new Map(
      [...this.map.entries()].filter(([key]) => key.startsWith(options.prefix)),
    );
  }
  entries(): [string, unknown][] {
    return [...this.map.entries()];
  }
}

const make = (storage: FakeStorage) => new RegistryDO(storage);
const serve = (registry: RegistryDO, path: string, init?: RequestInit): Promise<Response> =>
  registry.fetch(new Request(`https://do.internal${path}`, init));
const post = (registry: RegistryDO, path: string, body: unknown): Promise<Response> =>
  serve(registry, path, { method: "POST", body: JSON.stringify(body) });
const bodyOf = async (response: Response): Promise<Record<string, unknown>> =>
  (await response.json()) as Record<string, unknown>;

const createBody = (itemId: string, itemClass: string, extra?: Record<string, unknown>) => ({
  register_id: "unidpp-dev",
  item_id: itemId,
  class: itemClass,
  definition: `The ${itemId} item`,
  version: "1.0.0",
  ...extra,
});

// A signed service descriptor body: the operator block and the
// signature block are copied from the seed corpus (the release's
// deterministic dev keyring), so the content-derived key id the
// intake checks against matches.
const seedServiceBody = {
  identifier: "svc-probe-v1",
  operator: {
    algorithm: "ed25519",
    id: "op-763b38314f0f1189",
    key_id: "k-100fefc84e442ed0",
    label: "unidpp-archive",
    public_key: "23fda9a11d2b3df752a9da23d6d2892b7a39861030bae94db68f5cb7048588e3",
  },
  class: "archive",
  endpoints: [{ uri: "https://svc-probe.unidpp.org/", protocol_binding_ref: "pb-tier-a-binary" }],
  protocol_binding_ref: "pb-tier-a-binary",
  jurisdiction: "ZZ",
  residency_class: "anywhere",
  status: "active",
  version: "1.0.0",
  effective_from: "2026-09-01T00:00:00Z",
};
const seedSignature = {
  algorithm: "ed25519",
  key_id: "k-100fefc84e442ed0",
  value:
    "9d83809554cf576824567eb5146fafbebb0387372beba2bf43761f4e0105662f50be579990eb602b9b10610d76e1c6d476397c511f36e2269170936f57070204",
};

const seedBindingBody = {
  identifier: "pb-probe",
  description: "The probe binding",
  version: "1.0.0",
  grammar_ref: "https://unidpp.org/spec/probe",
  media_types: ["application/vnd.probe+json"],
  conformance_suite_ref: "https://unidpp.org/spec/probe/conformance",
  operator: {
    algorithm: "ed25519",
    id: "op-aa3344a691621b23",
    key_id: "k-d4613a88f0255bf5",
    label: "unidpp-registry",
    public_key: "e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f",
  },
};
const seedBindingSignature = {
  algorithm: "ed25519",
  key_id: "k-d4613a88f0255bf5",
  value:
    "8b1810c64059624ad64e82c772134e41669e8a9e6e8ea2309cb133664fefccc868afcd17b1471753a2f1a6e613f66e1d1bead55883cbb0a9dad8841ab7bed505",
};

describe("the registry parity surface", () => {
  it("serves the discovery document at the module root", async () => {
    const registry = make(new FakeStorage());
    const response = await serve(registry, "/");
    expect(response.status).toBe(200);
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = await bodyOf(response);
    expect(doc["service"]).toBe("unidpp-registry");
    expect(doc["version"]).toBe("0.1.0");
    expect(doc["item_classes"]).toContain("cross-register-mapping");
    expect(doc["service_classes"]).toContain("marketplace-gate");
    expect(doc["service_statuses"]).toContain("succeeded");
    expect(doc["statuses"]).toEqual(["valid", "superseded", "retired"]);
    expect(doc["intake_checks"]).toContain("instance-against-class");
    expect(doc["class_descriptors"]).toEqual([]);
    const subregisters = doc["subregisters"] as Record<string, { class: string; path: string }>;
    expect(subregisters["units"]).toEqual({ class: "unit", path: "/units" });
    expect(subregisters["instances"]).toEqual({ class: "instance", path: "/instances" });
    const endpoints = doc["endpoints"] as Record<string, string>;
    expect(endpoints["supersession_chain"]).toBe("GET /items/{id}/supersession?from=");
    expect(endpoints["audit_log"]).toBe("GET /admin/log?limit=&offset=");
    const asOf = doc["as_of"] as Record<string, string>;
    expect(asOf["response_header"]).toBe("x-as-of");
  });

  it("seeds the dataset once and reports the counts", async () => {
    const registry = make(new FakeStorage());
    const seeded = await post(registry, "/admin/seed", {});
    expect(seeded.status).toBe(200);
    const report = await bodyOf(seeded);
    expect(report["status"]).toBe("seeded");
    expect(report["counts"]).toEqual({
      services: 8,
      protocol_bindings: 5,
      verification_mechanisms: 3,
      units: 10,
    });
    const again = await bodyOf(await post(registry, "/admin/seed", {}));
    expect(again["status"]).toBe("already-seeded");
    const units = (await (await serve(registry, "/units")).json()) as { count: number };
    expect(units.count).toBe(10);
    const services = (await (await serve(registry, "/services")).json()) as {
      count: number;
      services: { identifier: string; kind: string }[];
    };
    expect(services.count).toBe(8);
    expect(services.services.map((s) => s.identifier)).toContain("unidpp-registry-v1");
    expect(services.services.every((s) => s.kind === "service")).toBe(true);
  });

  it("states the audit log with paging", async () => {
    const registry = make(new FakeStorage());
    await post(registry, "/items", createBody("urn:x:logged", "profile"));
    await serve(registry, "/items/urn:x:logged/versions", {
      method: "POST",
      body: JSON.stringify({ version: "1.1.0", reason: "the parity supersession" }),
    });
    const log = await bodyOf(await serve(registry, "/admin/log"));
    expect(log["total"]).toBe(2);
    expect(log["offset"]).toBe(0);
    const records = log["records"] as Record<string, unknown>[];
    expect(records[0]["op"]).toBe("register-item");
    expect(records[0]["seq"]).toBe(1);
    expect(typeof records[0]["recorded_at"]).toBe("string");
    expect(records[1]["op"]).toBe("supersede-version");
    expect(records[1]["prior_status"]).toBe("valid");
    expect(records[1]["superseded_version"]).toBe("1.0.0");
    const paged = await bodyOf(await serve(registry, "/admin/log?limit=1&offset=1"));
    expect(paged["total"]).toBe(2);
    expect((paged["records"] as unknown[]).length).toBe(1);
    expect((paged["records"] as Record<string, unknown>[])[0]["op"]).toBe("supersede-version");
  });

  it("serves the supersession chain and its from param", async () => {
    const registry = make(new FakeStorage());
    await post(registry, "/items", createBody("urn:x:chain", "profile"));
    await serve(registry, "/items/urn:x:chain/versions", {
      method: "POST",
      body: JSON.stringify({ version: "1.1.0", reason: "second" }),
    });
    await serve(registry, "/items/urn:x:chain/versions", {
      method: "POST",
      body: JSON.stringify({ version: "1.2.0", reason: "third" }),
    });
    const chain = await bodyOf(await serve(registry, "/items/urn:x:chain/supersession"));
    expect(chain["identifier"]).toBe("urn:x:chain");
    const versions = chain["chain"] as Record<string, unknown>[];
    expect(versions.map((v) => v.version)).toEqual(["1.0.0", "1.1.0", "1.2.0"]);
    expect(versions[0]["superseded_by_version"]).toBe("1.1.0");
    expect(versions[0]["window_end"]).toBe(versions[1]["effective_from"]);
    expect((chain["terminal"] as Record<string, unknown>)["version"]).toBe("1.2.0");
    const from = await bodyOf(
      await serve(registry, "/items/urn:x:chain/supersession?from=1.1.0"),
    );
    expect((from["chain"] as unknown[]).length).toBe(2);
    const badFrom = await serve(registry, "/items/urn:x:chain/supersession?from=9.9.9");
    expect(badFrom.status).toBe(400);
    expect((await bodyOf(badFrom))["error"]).toBe("item `urn:x:chain` has no version `9.9.9`");
    const absent = await serve(registry, "/items/urn:x:absent/supersession");
    expect(absent.status).toBe(404);
    expect((await bodyOf(absent))["error"]).toBe("no registry item `urn:x:absent`");
  });

  it("mounts the generic class surface at each plural", async () => {
    const registry = make(new FakeStorage());
    const created = await post(registry, "/units", {
      register_id: "unidpp-dev",
      item_id: "unit-probe",
      definition: "The probe unit",
      version: "1.0.0",
    });
    expect(created.status).toBe(201);
    expect((await bodyOf(created))["item_class"]).toBe("unit");
    // A body naming another class refuses (the mount is class-fixed).
    const mismatch = await post(registry, "/units", {
      register_id: "unidpp-dev",
      item_id: "urn:x:mismatch",
      class: "profile",
      definition: "The mismatch",
      version: "1.0.0",
    });
    expect(mismatch.status).toBe(400);
    expect((await bodyOf(mismatch))["error"]).toBe(
      "class `profile` does not match subregister `units`",
    );
    const unknownClass = await post(registry, "/units", {
      register_id: "unidpp-dev",
      item_id: "urn:x:widget",
      class: "widget",
      definition: "The widget",
      version: "1.0.0",
    });
    expect((await bodyOf(unknownClass))["error"]).toBe("unknown item class `widget`");
    const one = await serve(registry, "/units/unit-probe");
    expect(one.status).toBe(200);
    const superseded = await post(registry, "/units/unit-probe/versions", {
      version: "2.0.0",
      reason: "the unit supersession",
    });
    expect(superseded.status).toBe(201);
    const chain = await bodyOf(await serve(registry, "/units/unit-probe/supersession"));
    expect((chain["chain"] as unknown[]).length).toBe(2);
    // A cross-class id on the mount is the item miss.
    const scoped = await post(registry, "/items", createBody("urn:x:other", "profile"));
    expect(scoped.status).toBe(201);
    const wrongClass = await serve(registry, "/units/urn:x:other");
    expect(wrongClass.status).toBe(404);
    expect((await bodyOf(wrongClass))["error"]).toBe("no registry item `urn:x:other`");
    const wrongVersions = await post(registry, "/units/urn:x:other/versions", {
      version: "2.0.0",
      reason: "nope",
    });
    expect(wrongVersions.status).toBe(404);
    const wrongChain = await serve(registry, "/units/urn:x:other/supersession");
    expect(wrongChain.status).toBe(404);
    // Models keep their dedicated surface (no generic mount).
    const modelMount = await post(registry, "/models", { register_id: "r" });
    expect(modelMount.status).toBe(400);
  });

  it("binds applicability and evaluates the clock predicates", async () => {
    const registry = make(new FakeStorage());
    await post(registry, "/items", createBody("urn:x:profile", "profile"));
    const bound = await post(registry, "/applicability", {
      product_type: "battery-cell",
      profile_id: "urn:x:profile",
      effective_from: "2020-01-01T00:00:00Z",
    });
    expect(bound.status).toBe(201);
    const binding = await bodyOf(bound);
    expect(binding["subject"]).toBe("battery-cell");
    expect(binding["profile_item"]).toBe("urn:x:profile");
    expect(binding["retroactive"]).toBe(false);
    expect(binding["audit_seq"]).toBe(2);
    const query = await bodyOf(
      await serve(registry, "/applicability?product_type=battery-cell&at=2021-06-01T00:00:00Z"),
    );
    expect(query["product_type"]).toBe("battery-cell");
    // Non-retroactive: the binding registers now, so it does not
    // apply at 2021 even though its window started there.
    expect(query["applicability"]).toEqual([]);
    const retroactive = await post(registry, "/applicability", {
      product_type: "battery-cell",
      profile_id: "urn:x:profile",
      effective_from: "2020-01-01T00:00:00Z",
      retroactive: true,
    });
    expect(retroactive.status).toBe(201);
    const backdated = await bodyOf(
      await serve(registry, "/applicability?product_type=battery-cell&at=2021-06-01T00:00:00Z"),
    );
    expect((backdated["applicability"] as unknown[]).length).toBe(1);
    const missing = await serve(registry, "/applicability");
    expect(missing.status).toBe(400);
    expect((await bodyOf(missing))["error"]).toBe("`product_type` is required");
    const unknownProfile = await post(registry, "/applicability", {
      product_type: "x",
      profile_id: "urn:x:nope",
    });
    expect((await bodyOf(unknownProfile))["error"]).toBe(
      "profile item `urn:x:nope` is not registered",
    );
  });

  it("resolves clock-triggered profiles through the subject facts", async () => {
    const registry = make(new FakeStorage());
    await post(
      registry,
      "/items",
      createBody("urn:x:antique", "profile", {
        manifest: {
          version: "1.0.0",
          triggers: [
            { predicate_class: "time", basis: "manufactured_at", operator: ">=", duration: "P40Y" },
          ],
        },
      }),
    );
    await post(registry, "/applicability", {
      product_type: "antique-vehicle",
      profile_id: "urn:x:antique",
    });
    const unresolved = await bodyOf(
      await serve(registry, "/applicability?product_type=antique-vehicle"),
    );
    expect(unresolved["applicability"]).toEqual([]);
    const pending = (unresolved["unresolved"] as Record<string, unknown>[])[0];
    expect(pending["profile_item"]).toBe("urn:x:antique");
    expect(pending["reason"]).toBe(
      "the profile's triggers are clock predicates; supply subject_facts to evaluate them",
    );
    const facts = encodeURIComponent(
      JSON.stringify({ manufactured_at: "1962-05-01T00:00:00Z" }),
    );
    const fired = await bodyOf(
      await serve(registry, `/applicability?product_type=antique-vehicle&subject_facts=${facts}`),
    );
    const entries = fired["applicability"] as Record<string, unknown>[];
    expect(entries.length).toBe(1);
    const triggers = entries[0]["time_triggers"] as Record<string, unknown>[];
    expect(triggers[0]["threshold"]).toBe("2002-05-01T00:00:00Z");
    expect(triggers[0]["satisfied"]).toBe(true);
    const young = encodeURIComponent(
      JSON.stringify({ manufactured_at: "2020-05-01T00:00:00Z" }),
    );
    const notYet = await bodyOf(
      await serve(
        registry,
        `/applicability?product_type=antique-vehicle&subject_facts=${young}`,
      ),
    );
    expect(notYet["applicability"]).toEqual([]);
    expect(notYet["unresolved"]).toEqual([]);
    // The POST form carries the evaluation request too.
    const evaluated = await bodyOf(
      await post(registry, "/applicability", {
        product_type: "antique-vehicle",
        subject_facts: { manufactured_at: "1962-05-01T00:00:00Z" },
      }),
    );
    expect((evaluated["applicability"] as unknown[]).length).toBe(1);
    const conflict = await post(registry, "/applicability", {
      product_type: "x",
      profile_id: "p",
      subject_facts: { manufactured_at: "1962-05-01T00:00:00Z" },
    });
    expect(conflict.status).toBe(400);
    expect((await bodyOf(conflict))["error"]).toBe(
      "cannot bind with `subject_facts`: subject_facts marks an evaluation request (drop `profile_id`)",
    );
  });

  it("registers, reads, supersedes and chains C3 services", async () => {
    const registry = make(new FakeStorage());
    const empty = (await (await serve(registry, "/services")).json()) as { count: number };
    expect(empty.count).toBe(0);
    const refused = await post(registry, "/services", {});
    expect((await bodyOf(refused))["error"]).toBe("`identifier` is required");
    const noBody = await post(registry, "/services", { identifier: "svc-x", version: "1" });
    expect((await bodyOf(noBody))["error"]).toBe("missing `body`");
    const badClass = await post(registry, "/services", {
      identifier: "svc-x",
      version: "1",
      body: { ...seedServiceBody, identifier: "svc-x", class: "widget" },
      signature: seedSignature,
    });
    expect((await bodyOf(badClass))["error"]).toContain("unknown service class `widget`");
    const created = await post(registry, "/services", {
      identifier: "svc-probe-v1",
      version: "1.0.0",
      body: seedServiceBody,
      signature: seedSignature,
    });
    expect(created.status).toBe(201);
    const createView = await bodyOf(created);
    expect(createView["identifier"]).toBe("svc-probe-v1");
    expect((createView["version"] as Record<string, unknown>)["status"]).toBe("active");
    expect(typeof createView["audit_seq"]).toBe("number");
    const duplicate = await post(registry, "/services", {
      identifier: "svc-probe-v1",
      version: "1.1.0",
      body: seedServiceBody,
      signature: seedSignature,
    });
    expect(duplicate.status).toBe(409);
    const one = await bodyOf(await serve(registry, "/services/svc-probe-v1"));
    expect(one["kind"]).toBe("service");
    expect((one["version"] as Record<string, unknown>)["version"]).toBe("1.0.0");
    const superseded = await post(registry, "/services/svc-probe-v1/versions", {
      version: "2.0.0",
      body: { ...seedServiceBody, version: "2.0.0" },
      signature: seedSignature,
    });
    expect(superseded.status).toBe(201);
    const supersedeView = await bodyOf(superseded);
    expect((supersedeView["superseded_version"] as Record<string, unknown>)["version"]).toBe(
      "1.0.0",
    );
    const chain = await bodyOf(await serve(registry, "/services/svc-probe-v1/supersession"));
    expect((chain["chain"] as Record<string, unknown>[]).map((v) => v.version)).toEqual([
      "1.0.0",
      "2.0.0",
    ]);
    const absent = await serve(registry, "/services/svc-nope");
    expect(absent.status).toBe(404);
    expect((await bodyOf(absent))["error"]).toBe("no service descriptor `svc-nope`");
    const badFilter = await serve(registry, "/services?class=widget");
    expect(badFilter.status).toBe(400);
    expect((await bodyOf(badFilter))["error"]).toBe(
      "unknown service class `widget` (expected one of issuer, registry, resolver, trust, log, archive, gateway, marketplace-gate, edge)",
    );
    const scoped = (await (await serve(registry, "/services?class=archive")).json()) as {
      count: number;
    };
    expect(scoped.count).toBe(1);
    const jurisdiction = (await (
      await serve(registry, "/services?jurisdiction=JP")
    ).json()) as { count: number };
    expect(jurisdiction.count).toBe(0);
  });

  it("registers and reads C4 protocol bindings and C5 mechanisms", async () => {
    const registry = make(new FakeStorage());
    const created = await post(registry, "/protocol-bindings", {
      identifier: "pb-probe",
      version: "1.0.0",
      body: seedBindingBody,
      signature: seedBindingSignature,
    });
    expect(created.status).toBe(201);
    const createView = await bodyOf(created);
    expect((createView["binding"] as Record<string, unknown>)["grammar_ref"]).toBe(
      "https://unidpp.org/spec/probe",
    );
    const one = await bodyOf(await serve(registry, "/protocol-bindings/pb-probe"));
    expect(one["media_types"]).toEqual(["application/vnd.probe+json"]);
    expect(one["conformance_suite_ref"]).toBe("https://unidpp.org/spec/probe/conformance");
    const duplicate = await post(registry, "/protocol-bindings", {
      identifier: "pb-probe",
      version: "2.0.0",
      body: seedBindingBody,
      signature: seedBindingSignature,
    });
    expect(duplicate.status).toBe(409);
    const absent = await serve(registry, "/protocol-bindings/pb-nope");
    expect(absent.status).toBe(404);
    expect((await bodyOf(absent))["error"]).toBe("no protocol binding `pb-nope`");
    const list = (await (await serve(registry, "/protocol-bindings")).json()) as {
      count: number;
      protocol_bindings: unknown[];
    };
    expect(list.count).toBe(1);
    const mechanism = await post(registry, "/verification-mechanisms", {
      identifier: "vm-probe",
      body: {
        identifier: "vm-probe",
        suite: "Probe-Suite",
        agility_status: "active",
        trust_framework: "SIGNATIF",
        trust_list_endpoint: "https://trust.unidpp.org/probe",
        master_list_ref: "https://unidpp.org/spec/signatif/master-list",
        operator: seedBindingBody.operator,
      },
      signature: seedBindingSignature,
    });
    expect(mechanism.status).toBe(201);
    const mechanismView = await bodyOf(mechanism);
    expect((mechanismView["mechanism"] as Record<string, unknown>)["suite"]).toBe("Probe-Suite");
    const mechanismOne = await bodyOf(await serve(registry, "/verification-mechanisms/vm-probe"));
    expect(mechanismOne["trust_list_endpoint"]).toBe("https://trust.unidpp.org/probe");
    const mechanismAbsent = await serve(registry, "/verification-mechanisms/vm-nope");
    expect(mechanismAbsent.status).toBe(404);
    expect((await bodyOf(mechanismAbsent))["error"]).toBe(
      "no verification mechanism `vm-nope`",
    );
    const noOperator = await post(registry, "/verification-mechanisms", {
      identifier: "vm-x",
      body: { suite: "s", agility_status: "active" },
      signature: seedBindingSignature,
    });
    expect((await bodyOf(noOperator))["error"]).toBe("body missing `operator`");
  });

  it("serves the generated profile-manifest schema", async () => {
    const registry = make(new FakeStorage());
    const response = await serve(registry, "/schemas/profile-manifest");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/schema+json");
    const schema = await bodyOf(response);
    expect(schema["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(schema["$id"]).toBe("https://unidpp.org/schemas/profile-manifest/v1");
    expect(schema["required"]).toEqual(["version"]);
    expect(typeof schema["as_of"]).toBe("string");
    const defs = schema["$defs"] as Record<string, unknown>;
    expect(Object.keys(defs).sort()).toEqual([
      "data_point",
      "legal_basis",
      "transform",
      "trigger",
    ]);
  });

  it("deposits, reads, hash-pins and revalidates EXPRESS models", async () => {
    const registry = make(new FakeStorage());
    const empty = (await (await serve(registry, "/models")).json()) as { count: number };
    expect(empty.count).toBe(0);
    const deposited = await post(registry, "/models", {
      register_id: "unidpp-dev",
      item_id: "urn:x:model",
      title: "The probe EXPRESS schema",
      version: "1.0.0",
      source: "SCHEMA probe_schema;\nEND;\n",
    });
    expect(deposited.status).toBe(201);
    const deposit = await bodyOf(deposited);
    expect(deposit["item_class"]).toBe("model");
    expect(deposit["content_hash"]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(deposit["validation"]).toEqual({
      status: "pending",
      tool: "expressir",
      detail: "`expressir` is not available (gem install expressir)",
    });
    const listing = await bodyOf(await serve(registry, "/models"));
    const models = listing["models"] as Record<string, unknown>[];
    expect(listing["count"]).toBe(1);
    expect(models[0]["validation"]).toBe("pending");
    expect(models[0]["identifier"]).toBe("urn:x:model");
    const one = await bodyOf(await serve(registry, "/models/urn:x:model"));
    expect(one["source"]).toBe("SCHEMA probe_schema;\nEND;\n");
    expect(one["content_hash"]).toBe(deposit["content_hash"]);
    const pinned = await serve(registry, `/models/urn:x:model?hash=${deposit["content_hash"]}`);
    expect(pinned.status).toBe(200);
    const mismatched = await serve(registry, "/models/urn:x:model?hash=sha256:deadbeef");
    expect(mismatched.status).toBe(409);
    expect((await bodyOf(mismatched))["error"]).toContain(
      `content hash mismatch: the deposit is \`${deposit["content_hash"]}\` but \`sha256:deadbeef\` was pinned`,
    );
    const validated = await bodyOf(await post(registry, "/models/urn:x:model/validate", {}));
    expect(validated["identifier"]).toBe("urn:x:model");
    expect((validated["validation"] as Record<string, unknown>)["status"]).toBe("pending");
    const absent = await serve(registry, "/models/urn:x:nope");
    expect(absent.status).toBe(404);
    expect((await bodyOf(absent))["error"]).toBe("no model item `urn:x:nope`");
  });

  it("lists and directionally looks up cross-register mappings", async () => {
    const registry = make(new FakeStorage());
    await post(registry, "/items", createBody("urn:x:source-item", "data-element"));
    await post(registry, "/items", createBody("urn:x:target-item", "data-element"));
    const created = await post(registry, "/cross-register-mappings", {
      register_id: "unidpp-dev",
      item_id: "map-probe",
      definition: "The probe mapping",
      version: "1.0.0",
      manifest: {
        version: "1.0.0",
        source: { item: "urn:x:source-item", register: "unidpp-dev" },
        target: { item: "urn:x:target-item", register: "unidpp-dev" },
      },
    });
    expect(created.status).toBe(201);
    // Without the directional filters this is the generic listing.
    const generic = (await (await serve(registry, "/cross-register-mappings")).json()) as {
      count: number;
      items: unknown[];
    };
    expect(generic.count).toBe(1);
    const byItem = await bodyOf(
      await serve(registry, "/cross-register-mappings?item=urn:x:source-item"),
    );
    expect(byItem["count"]).toBe(1);
    expect((byItem["mappings"] as unknown[]).length).toBe(1);
    expect(byItem["query"]).toEqual({
      item: "urn:x:source-item",
      source: null,
      target: null,
    });
    const bySource = (await (
      await serve(registry, "/cross-register-mappings?source=urn:x:nobody")
    ).json()) as { count: number };
    expect(bySource.count).toBe(0);
    // The `register` filter alone is the generic class-scoped listing.
    const byRegister = (await (
      await serve(registry, "/cross-register-mappings?register=unidpp-dev")
    ).json()) as { count: number; items: unknown[] };
    expect(byRegister.count).toBe(1);
    const scoped = await serve(registry, "/cross-register-mappings/map-probe");
    expect(scoped.status).toBe(200);
    expect((await bodyOf(scoped))["item_class"]).toBe("cross-register-mapping");
    const superseded = await post(registry, "/cross-register-mappings/map-probe/versions", {
      version: "1.1.0",
      reason: "the mapping supersession",
    });
    expect(superseded.status).toBe(201);
    const chain = await bodyOf(
      await serve(registry, "/cross-register-mappings/map-probe/supersession"),
    );
    expect((chain["chain"] as unknown[]).length).toBe(2);
  });

  it("replays the journal into a fresh instance across the surfaces", async () => {
    const storage = new FakeStorage();
    const first = make(storage);
    await post(first, "/admin/seed", {});
    await post(first, "/items", createBody("urn:x:replayed", "profile"));
    await serve(first, "/items/urn:x:replayed/versions", {
      method: "POST",
      body: JSON.stringify({ version: "1.1.0", reason: "replayed" }),
    });
    await post(first, "/applicability", {
      product_type: "replayed-subject",
      profile_id: "urn:x:replayed",
    });
    const second = make(storage);
    const units = (await (await serve(second, "/units")).json()) as { count: number };
    expect(units.count).toBe(10);
    const services = (await (await serve(second, "/services")).json()) as { count: number };
    expect(services.count).toBe(8);
    const chain = await bodyOf(await serve(second, "/items/urn:x:replayed/supersession"));
    expect((chain["chain"] as Record<string, unknown>[]).map((v) => v.version)).toEqual([
      "1.0.0",
      "1.1.0",
    ]);
    const query = await bodyOf(
      await serve(second, "/applicability?product_type=replayed-subject"),
    );
    expect((query["applicability"] as unknown[]).length).toBe(1);
    const log = (await (await serve(second, "/admin/log")).json()) as { total: number };
    // The seed's 26 records + the register, supersede and bind.
    expect(log.total).toBe(29);
  });
});
