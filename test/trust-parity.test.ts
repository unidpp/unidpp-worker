// The trust surface's parity gate: the routes the native unidpp-trust
// one-binary serves, ported onto the Durable Object, answer the same
// shapes over the DO's own state — the discovery document, the
// zero-count empty-state reads, the native error texts verbatim, the
// M-of-K master list, the live revocation readings, the operator
// surface, the gated-evidence release (the stated 403 naming the
// required scope), the admin bearer gate, and the journal replaying
// into a fresh instance. The key-id derivation pins to the live
// server's witness keys byte for byte.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { TrustDO } from "../src/trust-do";
import { useWorkerCore } from "../src/mount";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);

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
}

const make = (storage: FakeStorage, env: Record<string, string | undefined> = {}) =>
  new TrustDO(storage, env);

const serve = (
  trust: TrustDO,
  path: string,
  init?: RequestInit,
): Promise<Response> => trust.fetch(new Request(`https://do.internal${path}`, init));

const get = (trust: TrustDO, path: string): Promise<Response> => serve(trust, path);

const post = (trust: TrustDO, path: string, body: unknown, headers?: Record<string, string>): Promise<Response> =>
  serve(trust, path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const errorOf = async (response: Response): Promise<string> =>
  ((await response.json()) as { error: string }).error;

// The boundary's seeded signing: the operator key derived from a
// 32-byte material signs in the named domain, head_public reads the
// matching public, and the key id rides the signatif derivation —
// the same discipline the keyring carries.
const unhexT = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const hexT = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const put = (bytes: Uint8Array): { ptr: number; len: number } => {
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
};
const publicOfSeed = (seedHex: string): string => {
  const material = put(unhexT(seedHex));
  const out = core.unidpp_alloc(32);
  core.unidpp_head_public(material.ptr, out);
  const hex = hexT(new Uint8Array(core.memory.buffer, out, 32).slice());
  core.unidpp_free(material.ptr, 32);
  core.unidpp_free(out, 32);
  return hex;
};
const signDomain = (
  seedHex: string,
  domain: string,
  payload: Uint8Array,
): string => {
  const material = put(unhexT(seedHex));
  const domainB = put(new TextEncoder().encode(domain));
  const payloadB = put(payload);
  const out = core.unidpp_alloc(64);
  const rc = core.unidpp_sign_raw(material.ptr, domainB.ptr, domainB.len, payloadB.ptr, payloadB.len, out);
  const sig = hexT(new Uint8Array(core.memory.buffer, out, 64).slice());
  [material, domainB, payloadB].forEach((p) => core.unidpp_free(p.ptr, p.len));
  core.unidpp_free(out, 64);
  if (rc !== 0) throw new Error(`the boundary refused to sign: ${rc}`);
  return sig;
};
const keyIdOfPublic = (publicHex: string): string => {
  const bytes = unhexT(publicHex);
  const data = new Uint8Array(bytes.length + 1);
  data[0] = 6; // the ed25519 suite code
  data.set(bytes, 1);
  const input = put(data);
  const out = core.unidpp_alloc(32);
  core.unidpp_sha256(input.ptr, data.length, out);
  const digest = hexT(new Uint8Array(core.memory.buffer, out, 32).slice());
  core.unidpp_free(input.ptr, data.length);
  core.unidpp_free(out, 32);
  return `k-${digest.slice(0, 16)}`;
};
// The signatif canonical-fields framing: every field u32-LE
// length-prefixed, little-endian — the bytes the quorum signatures
// cover.
const u32le = (value: number): Uint8Array => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
};
const u64le = (value: number): Uint8Array => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
};
const fieldOf = (text: string): Uint8Array => new TextEncoder().encode(text);
const canonicalOf = (fields: Uint8Array[]): Uint8Array => {
  const parts = fields.map((f) => {
    const head = u32le(f.length);
    const out = new Uint8Array(head.length + f.length);
    out.set(head);
    out.set(f, head.length);
    return out;
  });
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const secsOf = (text: string): number => Math.floor(Date.parse(text) / 1000);

// The live server's seeded witness keys (unidpp-signatif's
// deterministic scenario seeds): the DO must derive the identical
// key ids the native serves at /master-list.
const WITNESS_KEYS = [
  {
    node: "witness-1",
    suite: "ed25519",
    public: "ec5886a9a9bb1930ba01094d366a3630f17629d79b3a6bf9b4a170733fcbec8c",
    key_id: "k-97971c4b58794a1d",
  },
  {
    node: "witness-2",
    suite: "ed25519",
    public: "84f89b80fda6cbe64a3cc7c4ac045571c1fa57c18f36895899a6ef2fc2d672ed",
    key_id: "k-c25e28fb1d02e517",
  },
  {
    node: "witness-3",
    suite: "ed25519",
    public: "8bd17c244e34d2c55dfccc4c4ef138d7bab28e6f23584eea0bc3e75e761b2f28",
    key_id: "k-6ed0b618c60f6d1b",
  },
];

const ROOT_KEY = {
  suite: "ed25519",
  public: "f42d5db482bea7bc5eee028b2cc80be27fc12357afda7f4388a4b842c0dd3571",
  key_id: "k-2c3220f86668538f",
};

const NOTIFIED_KEY = {
  suite: "ecdsa-p256",
  public:
    "04c799611bf9d79ff3ba0b2f71305bd1234fb74d45454c8a7537c384780a8d415e59324ead0cdc729e5f9be92b13018f1b496b984e7cce3c1a8838625718cb639a",
  key_id: "k-669bef167423f49e",
};

const SIG64 = "ab".repeat(64);

describe("the trust Durable Object's parity surface", () => {
  it("serves the discovery document at the module root", async () => {
    const trust = make(new FakeStorage());
    const response = await get(trust, "/");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = (await response.json()) as Record<string, unknown>;
    expect(doc.service).toBe("unidpp-trust");
    expect(doc.version).toBe("0.1.0");
    expect(doc.build_id).toBe("dev");
    expect(doc.description).toContain("M-of-K multi-witness master list");
    const signing = doc.signing as Record<string, unknown>;
    expect(signing.domain).toBe("tree-head");
    expect(signing.suites).toEqual(["ed25519", "ecdsa-p256"]);
    expect(signing.keyring_endpoint).toBe("/keyring");
    const endpoints = doc.endpoints as Record<string, string>;
    expect(endpoints.master_list).toBe("GET /master-list");
    expect(endpoints.trust_list_one).toBe("GET /trust-lists/{jur}?at=");
    expect(endpoints.upsert_master_entry).toBe("POST /master-list/entries");
    expect(endpoints.evidence_release).toContain("X-UniDPP-Scope");
    const semantics = doc.revocation_semantics as Record<string, unknown>;
    expect(semantics.prospective_reasons).toEqual([
      "key-compromise",
      "cessation",
      "supersession",
      "affiliation-change",
    ]);
    expect(semantics.retroactive_reasons).toEqual([
      "misissuance",
      "fraudulent-issuance",
      "authority-compromised",
    ]);
    const seedFixtures = doc.seed_fixtures as Record<string, unknown>;
    expect(seedFixtures.source).toContain("scenario_misissuance");
    expect(seedFixtures.enabled_by_default).toBe(false);
    expect(doc.auth).toContain("UNIDPP_TRUST_ADMIN_TOKEN");
  });

  it("reads the empty state with the native shapes and zero counts", async () => {
    const trust = make(new FakeStorage());
    const master = (await (await get(trust, "/master-list")).json()) as Record<string, unknown>;
    expect(master.m_of_k).toEqual({ m: 1, k: 0 });
    expect(master.witnesses).toEqual([]);
    expect(master.entries).toEqual([]);
    const graph = (await (await get(trust, "/graph")).json()) as Record<string, unknown>;
    expect(graph.node_count).toBe(0);
    expect(graph.edge_count).toBe(0);
    expect(graph.nodes).toEqual([]);
    expect(graph.edges).toEqual([]);
    const lists = (await (await get(trust, "/trust-lists")).json()) as Record<string, unknown>;
    expect(lists.count).toBe(0);
    expect(lists.trust_lists).toEqual([]);
    const revocations = (await (await get(trust, "/revocations")).json()) as Record<string, unknown>;
    expect(revocations.count).toBe(0);
    expect(revocations.revocations).toEqual([]);
    expect(revocations.query).toEqual({
      at: null,
      known_by: null,
      retroactive: null,
      subject: null,
      window: null,
    });
    expect(revocations.semantics).toBeTruthy();
    const evidence = (await (await get(trust, "/evidence")).json()) as Record<string, unknown>;
    expect(evidence.count).toBe(0);
    expect(evidence.items).toEqual([]);
    const log = (await (await get(trust, "/admin/log")).json()) as Record<string, unknown>;
    expect(log.total).toBe(0);
    expect(log.offset).toBe(0);
    expect(log.records).toEqual([]);
  });

  it("answers the native error texts on unknown ids and bad parameters", async () => {
    const trust = make(new FakeStorage());
    expect(await get(trust, "/operators/ghost")).toMatchObject({ status: 404 });
    expect(await errorOf(await get(trust, "/operators/ghost"))).toBe("no operator `ghost`");
    expect(await errorOf(await get(trust, "/trust-lists/zz"))).toBe("no trust list `zz`");
    expect(await errorOf(await get(trust, "/evidence/nope"))).toBe("no evidence `nope`");
    expect(await errorOf(await get(trust, "/anchor-bundle"))).toBe(
      "`jurisdiction` query parameter is required",
    );
    expect(await errorOf(await get(trust, "/anchor-bundle?jurisdiction=NOPE"))).toBe(
      "no trust list `NOPE`",
    );
    expect(await errorOf(await get(trust, "/graph?at=nonsense"))).toBe(
      "invalid `at` parameter: invalid timestamp `nonsense` (expected RFC 3339 UTC)",
    );
    expect(await errorOf(await get(trust, "/revocations?retroactive=maybe"))).toBe(
      "`retroactive` must be true/false: `maybe`",
    );
    expect(await errorOf(await get(trust, "/revocations?window=bogus"))).toBe(
      "`window` must be `START..END` or `START,END`: `bogus`",
    );
    expect(await errorOf(await get(trust, "/revocations?known_by=nope"))).toBe(
      "`known_by`: invalid timestamp `nope` (expected RFC 3339 UTC)",
    );
  });

  it("answers 405 on methods a routed path does not carry", async () => {
    const trust = make(new FakeStorage());
    expect((await get(trust, "/nodes")).status).toBe(405);
    expect((await serve(trust, "/graph", { method: "POST" })).status).toBe(405);
    expect((await get(trust, "/edges")).status).toBe(405);
    expect((await serve(trust, "/master-list", { method: "POST" })).status).toBe(405);
    expect((await get(trust, "/trust-lists/eu/entries")).status).toBe(405);
    expect((await serve(trust, "/operators/x", { method: "POST" })).status).toBe(405);
    // An unrouted path stays the stated 404.
    const missing = await get(trust, "/anchors");
    expect(missing.status).toBe(404);
    expect(await errorOf(missing)).toBe("no such path");
  });

  it("registers nodes with the native key-id derivation", async () => {
    const trust = make(new FakeStorage());
    const created = await post(trust, "/nodes", {
      id: "Eu-Root",
      kind: "root",
      keys: [ROOT_KEY],
    });
    expect(created.status).toBe(201);
    const node = (await created.json()) as Record<string, unknown>;
    expect(node.id).toBe("eu-root");
    expect(node.kind).toBe("root");
    expect(node.audit_seq).toBe(1);
    expect((node.keys as { key_id: string }[])[0].key_id).toBe("k-2c3220f86668538f");
    // The p256 witness: the SEC1 form derives the same id as the live server.
    const p256 = await post(trust, "/nodes", {
      id: "eu-notified",
      kind: "delegated",
      keys: [NOTIFIED_KEY],
    });
    expect(((await p256.json()) as { keys: { key_id: string }[] }).keys[0].key_id).toBe(
      "k-669bef167423f49e",
    );
    // The refusal texts.
    expect(await errorOf(await post(trust, "/nodes", {}))).toBe("`id` is required");
    expect(await errorOf(await post(trust, "/nodes", { id: "x" }))).toBe("`kind` is required");
    expect(await errorOf(await post(trust, "/nodes", { id: "x", kind: "root", keys: [{ key_id: "k-x", suite: "ed25519", public: "aa".repeat(32) }] }))).toBe(
      "`key_id` `k-x` does not match the declared public key",
    );
    expect(await errorOf(await post(trust, "/nodes", { id: "x", kind: "boss" }))).toBe(
      "unknown node kind `boss`",
    );
  });

  it("adds edges under the graph's structural validations", async () => {
    const trust = make(new FakeStorage());
    await post(trust, "/nodes", { id: "eu-root", kind: "root" });
    await post(trust, "/nodes", { id: "eu-notified", kind: "delegated" });
    const scope = {
      authority: { Only: ["eu"] },
      conditions: [],
      product_group: { Only: ["batteries", "electronics"] },
      profile_version: { Only: ["urn:unidpp:profile:eu-batt@3"] },
      window: { Within: { from: "2026-01-01T00:00:00Z", to: null } },
    };
    const edge = await post(trust, "/edges", {
      parent: "eu-root",
      child: "eu-notified",
      scope,
      signatures: [{ suite: "ed25519", key_id: "k-2c3220f86668538f", signature: SIG64 }],
    });
    expect(edge.status).toBe(201);
    const added = (await edge.json()) as Record<string, unknown>;
    expect(added.parent).toBe("eu-root");
    expect(typeof added.audit_seq).toBe("number");
    expect(await errorOf(await post(trust, "/edges", { parent: "ghost", child: "eu-notified", scope, signatures: [{ suite: "ed25519", key_id: "k-x", signature: SIG64 }] }))).toBe(
      "unknown node `ghost`",
    );
    expect(
      await errorOf(
        await post(trust, "/edges", {
          parent: "eu-notified",
          child: "eu-root",
          scope,
          signatures: [{ suite: "ed25519", key_id: "k-x", signature: SIG64 }],
        }),
      ),
    ).toBe(
      "validation error: edge eu-notified -> eu-root would close a cycle (trust graph must stay a DAG)",
    );
    expect(
      await errorOf(
        await post(trust, "/edges", {
          parent: "eu-root",
          child: "eu-notified",
          scope,
          signatures: [],
        }),
      ),
    ).toBe("delegation credential eu-root -> eu-notified failed signature verification");
    expect(
      await errorOf(
        await post(trust, "/edges", {
          parent: "eu-root",
          child: "eu-notified",
          scope: { authority: { Only: [] } },
          signatures: [{ suite: "ed25519", key_id: "k-x", signature: SIG64 }],
        }),
      ),
    ).toBe("scope violation: credential eu-root -> eu-notified carries a contradictory scope");
    const graph = (await (await get(trust, "/graph")).json()) as Record<string, unknown>;
    expect(graph.node_count).toBe(2);
    expect(graph.edge_count).toBe(1);
  });

  it("registers trust lists and upserts entries with the native refusals", async () => {
    const trust = make(new FakeStorage());
    const created = await post(trust, "/trust-lists", { jurisdiction: "eu", framework: "espr" });
    expect(created.status).toBe(201);
    const list = (await created.json()) as Record<string, unknown>;
    expect(list.jurisdiction).toBe("EU");
    expect(list.framework).toBe("espr");
    expect(await errorOf(await post(trust, "/trust-lists", { jurisdiction: "EU" }))).toBe(
      "trust list `EU` is already registered",
    );
    expect(await errorOf(await post(trust, "/trust-lists", {}))).toBe(
      "`jurisdiction` is required",
    );
    expect(await errorOf(await post(trust, "/trust-lists", { jurisdiction: "a/b" }))).toBe(
      "`jurisdiction` must be 1-256 characters without `/` or whitespace",
    );
    expect(await errorOf(await post(trust, "/trust-lists/ZZ/entries", { node: "eu-root", not_before: "2026-01-01T00:00:00Z" }))).toBe(
      "no trust list `ZZ`",
    );
    const entry = await post(trust, "/trust-lists/EU/entries", {
      node: "eu-root",
      not_before: "2026-01-01T00:00:00Z",
    });
    expect(entry.status).toBe(201);
    const upserted = (await entry.json()) as Record<string, unknown>;
    expect(upserted.jurisdiction).toBe("EU");
    expect(upserted.node).toBe("eu-root");
    expect(upserted.superseded_at).toBeNull();
    // The read: the jurisdiction renders as registered, the entry in
    // force at the default instant, out of force at an earlier as-of
    // (the point-in-time cache posture rides the header).
    const one = await get(trust, "/trust-lists/eu");
    expect(one.status).toBe(200);
    expect(one.headers.get("cache-control")).toBe("public, max-age=30, must-revalidate");
    const view = (await one.json()) as Record<string, unknown>;
    expect(view.jurisdiction).toBe("eu");
    expect(view.framework).toBe("espr");
    expect((view.entries as { in_force_at_as_of: boolean }[])[0].in_force_at_as_of).toBe(true);
    const past = await get(trust, "/trust-lists?at=2000-01-01T00:00:00Z");
    expect(past.headers.get("cache-control")).toBe("public, max-age=86400, immutable");
    const pastView = (await past.json()) as { trust_lists: { entries: { in_force_at_as_of: boolean }[] }[] };
    expect(pastView.trust_lists[0].entries[0].in_force_at_as_of).toBe(false);
    // The withdrawal: superseded_at takes the entry out of force.
    await post(trust, "/trust-lists/eu/entries", {
      node: "eu-root",
      not_before: "2026-01-01T00:00:00Z",
      superseded_at: "2026-06-01T00:00:00Z",
    });
    const withdrawn = (await (await get(trust, "/trust-lists?at=2026-07-01T00:00:00Z")).json()) as {
      trust_lists: { entries: { in_force_at_as_of: boolean }[] }[];
    };
    expect(withdrawn.trust_lists[0].entries[0].in_force_at_as_of).toBe(false);
  });

  it("replaces the witness set and upserts master entries under M-of-K", async () => {
    const trust = make(new FakeStorage());
    expect(await errorOf(await post(trust, "/master-list/witnesses", { witnesses: [] }))).toBe(
      "`m` (number >= 1) is required",
    );
    expect(await errorOf(await post(trust, "/master-list/witnesses", { m: 2 }))).toBe(
      "`witnesses` array is required",
    );
    expect(
      await errorOf(await post(trust, "/master-list/witnesses", { m: 0, witnesses: WITNESS_KEYS })),
    ).toBe("`m` must be >= 1");
    expect(
      await errorOf(await post(trust, "/master-list/witnesses", { m: 4, witnesses: WITNESS_KEYS })),
    ).toBe("`m` (4) cannot exceed `witnesses.len()` (3)");
    const set = await post(trust, "/master-list/witnesses", { m: 2, witnesses: WITNESS_KEYS });
    expect(set.status).toBe(201);
    const shape = (await set.json()) as {
      m: number;
      k: number;
      witnesses: { key_id: string }[];
    };
    expect(shape.m).toBe(2);
    expect(shape.k).toBe(3);
    // The derived key ids match the live server's witness table.
    expect(shape.witnesses.map((w) => w.key_id)).toEqual(
      WITNESS_KEYS.map((w) => w.key_id),
    );
    expect(
      await errorOf(
        await post(trust, "/master-list/entries", {
          node: "eu-root",
          attestations: [
            { witness: "ghost-w", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: "k-x", signature: SIG64 } },
          ],
        }),
      ),
    ).toBe("witness `ghost-w` is not registered");
    const entry = await post(trust, "/master-list/entries", {
      node: "eu-root",
      attestations: [
        { witness: "witness-1", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: "k-97971c4b58794a1d", signature: SIG64 } },
        { witness: "witness-2", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: "k-c25e28fb1d02e517", signature: SIG64 } },
      ],
    });
    expect(entry.status).toBe(201);
    const master = (await (await get(trust, "/master-list")).json()) as {
      m_of_k: { m: number; k: number };
      entries: {
        node: string;
        attestations: { verified: boolean }[];
        verified_witnesses: number;
        quorate: boolean;
        threshold_required: number;
      }[];
    };
    expect(master.m_of_k).toEqual({ m: 2, k: 3 });
    expect(master.entries[0].node).toBe("eu-root");
    expect(master.entries[0].threshold_required).toBe(2);
    // The stated degrade: the MasterListWitness domain is not
    // verifiable at the wasm boundary, so the verdicts render false
    // rather than invented.
    expect(master.entries[0].attestations[0].verified).toBe(false);
    expect(master.entries[0].verified_witnesses).toBe(0);
    expect(master.entries[0].quorate).toBe(false);
  });

  it("renders the anchor bundle and the operator surface", async () => {
    const trust = make(new FakeStorage());
    await post(trust, "/nodes", { id: "eu-root", kind: "root", keys: [ROOT_KEY] });
    await post(trust, "/nodes", {
      id: "eu-super-quorum",
      kind: {
        threshold_group: {
          threshold: 2,
          members: ["quorum-3", "quorum-1", "quorum-2"],
        },
      },
    });
    await post(trust, "/trust-lists", { jurisdiction: "EU", framework: "espr" });
    await post(trust, "/trust-lists/EU/entries", { node: "eu-root", not_before: "2026-01-01T00:00:00Z" });
    await post(trust, "/master-list/witnesses", { m: 2, witnesses: WITNESS_KEYS });
    await post(trust, "/master-list/entries", {
      node: "eu-root",
      attestations: [
        { witness: "witness-1", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: "k-97971c4b58794a1d", signature: SIG64 } },
      ],
    });
    const bundle = (await (await get(trust, "/anchor-bundle?jurisdiction=eu")).json()) as {
      jurisdiction: string;
      trust_lists: { jurisdiction: string; entries: unknown[] }[];
      master: {
        m: number;
        k: number;
        witnesses: Record<string, unknown>[];
        entries: Record<string, unknown>[];
      };
    };
    expect(bundle.jurisdiction).toBe("eu");
    expect(bundle.trust_lists[0].jurisdiction).toBe("EU");
    expect(bundle.trust_lists[0].entries).toHaveLength(1);
    expect(bundle.master.m).toBe(2);
    expect(bundle.master.k).toBe(3);
    // The verifier form carries no key_id on the bundle's witnesses
    // and no verdicts on its entries — the native AnchorBundle shape.
    expect(Object.keys(bundle.master.witnesses[0]).sort()).toEqual([
      "node",
      "public",
      "public_len",
      "suite",
    ]);
    expect(bundle.master.entries[0]).toEqual({
      node: "eu-root",
      attestations: [
        {
          witness: "witness-1",
          at: "2026-01-01T00:00:00Z",
          slot: { suite: "ed25519", key_id: "k-97971c4b58794a1d", signature: SIG64 },
        },
      ],
    });
    const operator = (await (await get(trust, "/operators/eu-root")).json()) as Record<string, unknown>;
    expect(operator.operator).toBe("eu-root");
    expect(operator.kind).toBe("Root");
    expect(operator.keys).toEqual([{ key_id: "k-2c3220f86668538f", suite: "ed25519" }]);
    expect(operator.delegated_by).toEqual([]);
    expect(operator.master_list).toEqual({ attested_by: 1, witnesses: ["witness-1"] });
    const memberships = operator.trust_list_memberships as { jurisdiction: string }[];
    expect(memberships).toHaveLength(1);
    expect(memberships[0].jurisdiction).toBe("EU");
    // The threshold group renders in the Rust Debug form, members sorted.
    const group = (await (await get(trust, "/operators/eu-super-quorum")).json()) as {
      kind: string;
    };
    expect(group.kind).toBe(
      'ThresholdGroup { threshold: 2, members: {NodeId("quorum-1"), NodeId("quorum-2"), NodeId("quorum-3")} }',
    );
  });

  it("verifies master-list attestations live and counts the quorum verdict", async () => {
    const trust = make(new FakeStorage());
    const seed = "cc".repeat(32);
    const pub = publicOfSeed(seed);
    const keyId = keyIdOfPublic(pub);
    const set = await post(trust, "/master-list/witnesses", {
      m: 1,
      witnesses: [{ node: "witness-t", suite: "ed25519", key_id: keyId, public: pub, public_len: 32 }],
    });
    expect(set.status).toBe(201);
    // The attestation signs the canonical bytes (node, at.secs,
    // at.nanos) in the MasterListWitness domain.
    const payload = canonicalOf([
      fieldOf("issuer-t"),
      u64le(secsOf("2026-01-01T00:00:00Z")),
      u32le(0),
    ]);
    const sig = signDomain(seed, "master-list-witness", payload);
    const entry = await post(trust, "/master-list/entries", {
      node: "issuer-t",
      attestations: [
        { witness: "witness-t", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: keyId, signature: sig } },
      ],
    });
    expect(entry.status).toBe(201);
    const read = async () =>
      (await (await get(trust, "/master-list")).json()) as {
        entries: {
          node: string;
          attestations: { verified: boolean }[];
          verified_witnesses: number;
          quorate: boolean;
        }[];
      };
    const good = (await read()).entries.find((e) => e.node === "issuer-t");
    expect(good?.attestations[0]?.verified).toBe(true);
    expect(good?.verified_witnesses).toBe(1);
    expect(good?.quorate).toBe(true);
    // A tampered signature renders unverified, never faked.
    const bad = sig.endsWith("00") ? `${sig.slice(0, -2)}01` : `${sig.slice(0, -2)}00`;
    await post(trust, "/master-list/entries", {
      node: "issuer-u",
      attestations: [
        { witness: "witness-t", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: keyId, signature: bad } },
      ],
    });
    const tampered = (await read()).entries.find((e) => e.node === "issuer-u");
    expect(tampered?.attestations[0]?.verified).toBe(false);
    expect(tampered?.quorate).toBe(false);
  });

  it("declares revocations and reads the live retroactivity", async () => {
    const trust = make(new FakeStorage());
    await post(trust, "/nodes", { id: "eu-root", kind: "root" });
    // The merits refusal: retroactive without a quorum attestation.
    expect(
      await errorOf(
        await post(trust, "/revocations", {
          subject: { kind: "key", id: "k-issuer" },
          reason: { token: "misissuance" },
          declared_at: "2026-03-01T00:00:00Z",
          declared_by: "eu-root",
          window: { start: "2026-01-01T00:00:00Z", end: "2026-02-01T00:00:00Z" },
        }),
      ),
    ).toBe("retroactive distrust of `key:k-issuer` requires a quorum attestation");
    // The prospective declaration needs no quorum.
    const prospective = await post(trust, "/revocations", {
      subject: { kind: "key", id: "k-issuer" },
      reason: { token: "key-compromise", after: "2026-02-15T00:00:00Z" },
      declared_at: "2026-03-02T00:00:00Z",
      declared_by: "eu-root",
      window: { start: "2026-02-15T00:00:00Z" },
    });
    expect(prospective.status).toBe(201);
    const declared = (await prospective.json()) as Record<string, unknown>;
    expect(declared.window).toEqual({ start: "2026-02-15T00:00:00Z", end: null, open: true });
    expect(declared.audit_seq).toBe(2);
    // The retroactive declaration rides with a quorate attestation:
    // two member keys registered on the graph, each signing the
    // canonical quorum payload in the Quorum domain — the intake
    // verifies before recording, exactly as the native does.
    const memberSeed1 = "aa".repeat(32);
    const memberSeed2 = "bb".repeat(32);
    const memberPublic1 = publicOfSeed(memberSeed1);
    const memberPublic2 = publicOfSeed(memberSeed2);
    await post(trust, "/nodes", {
      id: "quorum-1",
      kind: "end",
      keys: [
        { key_id: keyIdOfPublic(memberPublic1), suite: "ed25519", public: memberPublic1, public_len: 32 },
      ],
    });
    await post(trust, "/nodes", {
      id: "quorum-2",
      kind: "end",
      keys: [
        { key_id: keyIdOfPublic(memberPublic2), suite: "ed25519", public: memberPublic2, public_len: 32 },
      ],
    });
    const statement = canonicalOf([
      fieldOf("key:k-issuer"),
      fieldOf("misissuance"),
      fieldOf("eu-root"),
      u64le(secsOf("2026-01-01T00:00:00Z")),
      u64le(secsOf("2026-02-01T00:00:00Z")),
    ]);
    const quorumPayload = canonicalOf([fieldOf("eu-super-quorum")]);
    const payload = new Uint8Array(quorumPayload.length + 4 + statement.length);
    payload.set(quorumPayload);
    payload.set(u32le(2), quorumPayload.length);
    payload.set(statement, quorumPayload.length + 4);
    const signatureOf = (seed: string) => signDomain(seed, "quorum", payload);
    // The merits refusal when the attestation does not reach the
    // threshold: one member slot verifies, the threshold is two.
    expect(
      await errorOf(
        await post(trust, "/revocations", {
          subject: { kind: "key", id: "k-issuer" },
          reason: { token: "misissuance" },
          declared_at: "2026-03-01T12:00:00Z",
          declared_by: "eu-root",
          window: { start: "2026-01-01T00:00:00Z", end: "2026-02-01T00:00:00Z" },
          quorum: {
            quorum: "eu-super-quorum",
            threshold: 2,
            signatures: [
              {
                suite: "ed25519",
                key_id: keyIdOfPublic(memberPublic1),
                signature: signatureOf(memberSeed1),
              },
            ],
          },
        }),
      ),
    ).toBe(
      "quorum attestation for `key:k-issuer` does not reach the threshold (1 member key(s) verified, threshold 2)",
    );
    const retroactive = await post(trust, "/revocations", {
      subject: { kind: "key", id: "k-issuer" },
      reason: { token: "misissuance" },
      declared_at: "2026-03-01T12:00:00Z",
      declared_by: "eu-root",
      window: { start: "2026-01-01T00:00:00Z", end: "2026-02-01T00:00:00Z" },
      quorum: {
        quorum: "eu-super-quorum",
        threshold: 2,
        signatures: [
          {
            suite: "ed25519",
            key_id: keyIdOfPublic(memberPublic1),
            signature: signatureOf(memberSeed1),
          },
          {
            suite: "ed25519",
            key_id: keyIdOfPublic(memberPublic2),
            signature: signatureOf(memberSeed2),
          },
        ],
      },
    });
    expect(retroactive.status).toBe(201);
    const all = (await (await get(trust, "/revocations")).json()) as {
      count: number;
      revocations: {
        seq: number;
        reason: { token: string };
        standing_at_as_of: string;
        verifications_at_stand: boolean;
        rule: string;
        quorum: Record<string, unknown> | null;
        known_at_cutoff: boolean;
        voids_at_as_of: boolean;
      }[];
    };
    expect(all.count).toBe(2);
    const [compromise, misissuance] = all.revocations;
    expect(misissuance.seq).toBe(2);
    expect(misissuance.reason.token).toBe("misissuance");
    expect(misissuance.rule).toContain("retroactive");
    expect(misissuance.quorum).toMatchObject({
      quorum: "eu-super-quorum",
      threshold: 2,
      form: "member-keys",
      verified_count: 2,
      group_verified: false,
      quorate: true,
    });
    expect(compromise.reason.token).toBe("key-compromise");
    expect(compromise.quorum).toBeNull();
    expect(compromise.rule).toContain("prospective");
    // The compromise window is open-ended from its effect moment, so
    // the default as-of (now) sits inside it: suspended-from.
    expect(compromise.standing_at_as_of).toBe("suspended-from");
    // The filters.
    const retroOnly = (await (await get(trust, "/revocations?retroactive=true")).json()) as {
      count: number;
    };
    expect(retroOnly.count).toBe(1);
    const bySubject = (await (await get(trust, "/revocations?subject=key:k-issuer")).json()) as {
      count: number;
    };
    expect(bySubject.count).toBe(2);
    const none = (await (await get(trust, "/revocations?subject=key:k-other")).json()) as {
      count: number;
    };
    expect(none.count).toBe(0);
    // The evidentiary cutoff: a declaration made after it keeps prior
    // as-of verifications valid.
    const cutoff = (await (
      await get(trust, "/revocations?known_by=2026-03-01T00:00:00Z&at=2026-01-15T00:00:00Z")
    ).json()) as {
      known_by: string | null;
      revocations: { known_at_cutoff: boolean; voids_at_as_of: boolean; standing_at_as_of: string }[];
    };
    expect(cutoff.known_by).toBe("2026-03-01T00:00:00Z");
    expect(cutoff.revocations[0].known_at_cutoff).toBe(false);
    expect(cutoff.revocations[0].voids_at_as_of).toBe(false);
    expect(cutoff.revocations[0].standing_at_as_of).toBe("valid");
    // Inside the retroactive window the second declaration voids ab
    // initio; verifications at that instant stop standing.
    const insideWindow = (await (
      await get(trust, "/revocations?at=2026-01-15T00:00:00Z")
    ).json()) as {
      revocations: { standing_at_as_of: string; verifications_at_stand: boolean }[];
    };
    expect(insideWindow.revocations[1].standing_at_as_of).toBe("void-ab-initio");
    expect(insideWindow.revocations[1].verifications_at_stand).toBe(false);
    // Outside the window the same retroactive declaration re-validates.
    const outsideWindow = (await (
      await get(trust, "/revocations?at=2026-02-15T00:00:00Z")
    ).json()) as {
      revocations: { standing_at_as_of: string }[];
    };
    expect(outsideWindow.revocations[1].standing_at_as_of).toBe("valid");
    // The window filter returns declarations whose window overlaps.
    const overlapping = (await (
      await get(trust, "/revocations?window=2026-01-15T00:00:00Z..2026-01-20T00:00:00Z")
    ).json()) as {
      query: { window: { start: string; end: string | null } | null };
      count: number;
    };
    expect(overlapping.count).toBe(1);
    expect(overlapping.query.window).toEqual({
      start: "2026-01-15T00:00:00Z",
      end: "2026-01-20T00:00:00Z",
    });
  });

  it("registers and releases gated evidence with the stated refusal", async () => {
    const trust = make(new FakeStorage());
    const content = "%PDF-1.4 fake";
    const contentHex = Buffer.from(content, "utf8").toString("hex");
    expect(
      await errorOf(
        await post(trust, "/admin/evidence", { id: "ev", contentHex }),
      ),
    ).toBe("`requiredScope` is required — ungated evidence is a public link, not evidence");
    expect(await errorOf(await post(trust, "/admin/evidence", { id: "ev", requiredScope: "s" }))).toBe(
      "`contentHex` is required",
    );
    const created = await post(trust, "/admin/evidence", {
      id: "ev-ccc-cert",
      contentType: "application/pdf",
      description: "CCC change certificate",
      requiredScope: "market-surveillance",
      contentHex,
    });
    expect(created.status).toBe(201);
    const meta = (await created.json()) as Record<string, unknown>;
    expect(meta.id).toBe("ev-ccc-cert");
    expect(meta.required_scope).toBe("market-surveillance");
    expect(meta.content_bytes).toBe(content.length);
    expect(await errorOf(
      await post(trust, "/admin/evidence", {
        id: "ev-ccc-cert",
        requiredScope: "other",
        contentHex: "aa",
      }),
    )).toBe("evidence `ev-ccc-cert` is already registered");
    const catalogue = (await (await get(trust, "/evidence")).json()) as {
      count: number;
      items: Record<string, unknown>[];
    };
    expect(catalogue.count).toBe(1);
    expect(catalogue.items[0]).toEqual({
      id: "ev-ccc-cert",
      content_type: "application/pdf",
      description: "CCC change certificate",
      required_scope: "market-surveillance",
      content_bytes: content.length,
    });
    // An unsatisfying scope is the stated 403 naming the required
    // scope — never a silent 404.
    expect(await errorOf(await get(trust, "/evidence/ev-ccc-cert?scope=wrong"))).toBe(
      "evidence `ev-ccc-cert` requires scope `market-surveillance` — the request carried `wrong`",
    );
    expect(await errorOf(await get(trust, "/evidence/ev-ccc-cert"))).toBe(
      "evidence `ev-ccc-cert` requires scope `market-surveillance` — the request carried ``",
    );
    const release = await get(
      trust,
      "/evidence/ev-ccc-cert?scope=market-surveillance&requester=customs-de",
    );
    expect(release.status).toBe(200);
    expect(release.headers.get("content-type")).toBe("application/pdf");
    expect(release.headers.get("x-unidpp-scope")).toBe("market-surveillance");
    expect(await release.text()).toBe(content);
    // The header form: the parameter outranks it when both arrive.
    const viaHeader = await get(trust, "/evidence/ev-ccc-cert").then((r) => r);
    expect(viaHeader.status).toBe(403);
    const released = await serve(trust, "/evidence/ev-ccc-cert", {
      headers: { "x-unidpp-scope": "market-surveillance" },
    });
    expect(released.status).toBe(200);
    // Every release is journaled with its requester; the denial is not.
    const log = (await (await get(trust, "/admin/log")).json()) as {
      total: number;
      records: { op: string; body: Record<string, unknown> }[];
    };
    expect(log.total).toBe(3);
    expect(log.records.map((r) => r.op)).toEqual([
      "register-evidence",
      "evidence-released",
      "evidence-released",
    ]);
    expect(log.records[1].body).toEqual({
      id: "ev-ccc-cert",
      requester: "customs-de",
      scope: "market-surveillance",
    });
    expect(log.records[2].body.requester).toBeNull();
  });

  it("gates the operator surface on the deployment's bearer token", async () => {
    const gated = make(new FakeStorage(), { UNIDPP_TRUST_ADMIN_TOKEN: "sekrit" });
    const refused = await post(gated, "/nodes", { id: "n", kind: "root" });
    expect(refused.status).toBe(401);
    expect(await errorOf(refused)).toBe("unauthorized");
    expect((await get(gated, "/admin/log")).status).toBe(401);
    const wrong = await post(gated, "/nodes", { id: "n", kind: "root" }, {
      authorization: "Bearer nope",
    });
    expect(wrong.status).toBe(401);
    const allowed = await post(gated, "/nodes", { id: "n", kind: "root" }, {
      authorization: "Bearer sekrit",
    });
    expect(allowed.status).toBe(201);
    const logWithToken = await serve(gated, "/admin/log", {
      headers: { authorization: "Bearer sekrit" },
    });
    expect(logWithToken.status).toBe(200);
    // Reads stay public with a token configured.
    expect((await get(gated, "/graph")).status).toBe(200);
    // An unconfigured deployment serves open, as the native dev mode.
    const open = make(new FakeStorage());
    expect((await post(open, "/nodes", { id: "n", kind: "root" })).status).toBe(201);
  });

  it("replays the journal into a fresh instance", async () => {
    const storage = new FakeStorage();
    const first = make(storage);
    await post(first, "/nodes", { id: "eu-root", kind: "root", keys: [ROOT_KEY] });
    await post(first, "/nodes", { id: "eu-notified", kind: "delegated" });
    await post(first, "/edges", {
      parent: "eu-root",
      child: "eu-notified",
      scope: { authority: { Only: ["eu"] }, conditions: [] },
      signatures: [{ suite: "ed25519", key_id: "k-2c3220f86668538f", signature: SIG64 }],
    });
    await post(first, "/trust-lists", { jurisdiction: "EU", framework: "espr" });
    await post(first, "/trust-lists/EU/entries", { node: "eu-root", not_before: "2026-01-01T00:00:00Z" });
    await post(first, "/master-list/witnesses", { m: 2, witnesses: WITNESS_KEYS });
    await post(first, "/master-list/entries", {
      node: "eu-root",
      attestations: [
        { witness: "witness-1", at: "2026-01-01T00:00:00Z", slot: { suite: "ed25519", key_id: "k-97971c4b58794a1d", signature: SIG64 } },
      ],
    });
    await post(first, "/revocations", {
      subject: { kind: "node", id: "eu-notified" },
      reason: { token: "cessation" },
      declared_at: "2026-05-01T00:00:00Z",
      declared_by: "eu-root",
      window: { start: "2026-05-01T00:00:00Z" },
    });
    await post(first, "/admin/evidence", {
      id: "ev-x",
      requiredScope: "s",
      contentHex: Buffer.from("bytes", "utf8").toString("hex"),
    });
    await get(first, "/evidence/ev-x?scope=s");
    const second = make(storage);
    const graph = (await (await get(second, "/graph")).json()) as {
      node_count: number;
      edge_count: number;
      nodes: { id: string; keys: unknown[] }[];
    };
    expect(graph.node_count).toBe(2);
    expect(graph.edge_count).toBe(1);
    expect(graph.nodes.find((n) => n.id === "eu-root")?.keys).toHaveLength(1);
    const list = (await (await get(second, "/trust-lists/EU")).json()) as {
      entries: unknown[];
    };
    expect(list.entries).toHaveLength(1);
    const master = (await (await get(second, "/master-list")).json()) as {
      m_of_k: { m: number; k: number };
      entries: unknown[];
    };
    expect(master.m_of_k).toEqual({ m: 2, k: 3 });
    expect(master.entries).toHaveLength(1);
    const revocations = (await (await get(second, "/revocations")).json()) as {
      count: number;
    };
    expect(revocations.count).toBe(1);
    const evidence = (await (await get(second, "/evidence")).json()) as { count: number };
    expect(evidence.count).toBe(1);
    const released = await get(second, "/evidence/ev-x?scope=s");
    expect(await released.text()).toBe("bytes");
    const log = (await (await get(second, "/admin/log")).json()) as { total: number };
    // Nine mutations plus the first instance's release, then the
    // replayed instance's own release — the audit trail is the journal.
    expect(log.total).toBe(11);
    const operator = (await (await get(second, "/operators/eu-root")).json()) as {
      kind: string;
      delegates: unknown[];
    };
    expect(operator.kind).toBe("Root");
    expect(operator.delegates).toHaveLength(1);
  });

  it("keeps the keyring and receipt verification working unchanged", async () => {
    const trust = make(new FakeStorage());
    const keyring = (await (await get(trust, "/keyring")).json()) as {
      mode: string;
      domain: string;
      roles: Record<string, { key_id: string; public: string; public_len: number; suite: string }>;
    };
    expect(keyring.mode).toBe("seeded-dev");
    expect(keyring.domain).toBe("tree-head");
    expect(keyring.roles["sign-ed25519"].public_len).toBe(32);
    expect(keyring.roles["sign-ecdsa-p256"].public_len).toBe(65);
    expect(keyring.roles["sign-ed25519"].key_id).toMatch(/^k-[0-9a-f]{16}$/);
    // The response signature verifies over the exact body bytes in
    // the tree-head domain, under the served signing key.
    const response = await get(trust, "/trust-lists");
    const body = await response.text();
    const sig = response.headers.get("x-sig-ed25519");
    const keyId = response.headers.get("x-sig-key-id-ed25519");
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(keyId).toBe(keyring.roles["sign-ed25519"].key_id);
    expect(response.headers.get("x-sig-domain")).toBe("tree-head");
    expect(response.headers.get("etag")).toBe(`"sig-${sig?.slice(0, 32)}"`);
    // The stranger's check, in-process: the served signature verifies
    // under the served public over the exact body bytes.
    const { createPublicKey, verify } = await import("node:crypto");
    const spki = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(keyring.roles["sign-ed25519"].public, "hex"),
    ]);
    // The signature covers the framed bytes: the domain tag, a zero
    // separator, then the body — what the native slot sign/verify pair
    // frames on both sides.
    const framed = Buffer.concat([
      Buffer.from("UNIDPP-SIGNATIF/TREE-HEAD"),
      Buffer.from([0]),
      Buffer.from(body, "utf8"),
    ]);
    expect(
      verify(
        null,
        framed,
        createPublicKey({ key: spki, format: "der", type: "spki" }),
        Buffer.from(sig ?? "", "hex"),
      ),
    ).toBe(true);
    const missing = await post(trust, "/verify", {});
    expect(missing.status).toBe(400);
    expect(await errorOf(missing)).toBe("`tree_head` is required");
    const verdict = (await (
      await post(trust, "/verify", {
        tree_head: {
          log_id: "unidpp-log",
          tree_size: 1,
          timestamp: "2026-01-01T00:00:00Z",
          root: "aa".repeat(32),
          signature: { suite: "ed25519", key_id: keyring.roles["sign-ed25519"].key_id, signature: "bb".repeat(64) },
        },
      })
    ).json()) as { verified: boolean; log_id: string };
    expect(verdict.verified).toBe(false);
    expect(verdict.log_id).toBe("unidpp-log");
    const health = await get(trust, "/healthz");
    expect(health.status).toBe(200);
    // The native trust's healthz: the service and the instant in the
    // body, signed like every trust answer.
    expect(health.headers.get("x-sig-domain")).toBe("tree-head");
    expect(health.headers.get("x-sig-ed25519")).toBeTruthy();
    const healthBody = (await health.json()) as {
      status?: string;
      service?: string;
      as_of?: string;
    };
    expect(healthBody.status).toBe("ok");
    expect(healthBody.service).toBe("unidpp-trust");
    expect(healthBody.as_of).toBeTruthy();
  });
});
