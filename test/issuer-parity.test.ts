// The issuer's contract-parity gates: the discovery document, the
// verdict (the log leg, the event-signature audit and the Tier-A
// carrier leg over the DO's own state), the admin surface (profiles,
// applicability, the audit log) and the operator guard — the shapes
// the native issuer serves, stated against the DO.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const serve = (issuer: IssuerDO, path: string, init?: RequestInit): Promise<Response> =>
  issuer.fetch(new Request(`https://do.internal${path}`, init));

const mintPassport = async (issuer: IssuerDO, identity: string): Promise<string> => {
  const minted = await serve(issuer, "/passports", {
    method: "POST",
    body: JSON.stringify({ identity }),
  });
  expect(minted.status).toBe(201);
  const body = (await minted.json()) as { passport_id: string };
  return body.passport_id;
};

describe("the issuer discovery document", () => {
  it("serves the native's bare-prefix answer", async () => {
    const issuer = new IssuerDO(storage());
    const response = await serve(issuer, "/");
    expect(response.status).toBe(200);
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = (await response.json()) as Record<string, unknown>;
    expect(doc.service).toBe("unidpp-issuer");
    expect(doc.version).toBe("0.1.0");
    expect(doc.build_id).toBe("dev");
    expect(doc.keyring_mode).toBe("seeded-dev");
    expect(doc.registry).toBe(null);
    expect(doc.auth).toBe(
      "mutations require a Bearer token when UNIDPP_ISSUER_ADMIN_TOKEN is set",
    );
    const endpoints = doc.endpoints as Record<string, string>;
    expect(endpoints.verdict).toBe("GET /passports/{id}/verdict?at=&max_age=");
    expect(endpoints.audit_log).toBe("GET /admin/log?limit=&offset=");
    expect(endpoints.bind_applicability).toBe("POST /admin/applicability");
    // Every answer is as-of stamped: the header plus the body field.
    expect(typeof doc.as_of).toBe("string");
  });
});

describe("the keyring document", () => {
  it("states the event and pack roles the surface signs under", async () => {
    const issuer = new IssuerDO(storage());
    const response = await serve(issuer, "/keyring");
    expect(response.status).toBe(200);
    const doc = (await response.json()) as {
      dev_seed: string;
      mode: string;
      roles: {
        event: { suite: string; key_id: string; public: string; public_serialized: string };
        pack: {
          suite: string;
          key_id: string;
          public: string;
          public_serialized: string;
          suites: Record<string, { suite: string; public: string }>;
        };
      };
      warning: string;
    };
    expect(doc.mode).toBe("seeded-dev");
    expect(doc.dev_seed).toBe("unidpp-issuer/dev-1");
    expect(doc.roles.event.suite).toBe("ed25519");
    expect(doc.roles.event.key_id).toMatch(/^k-[0-9a-f]{16}$/);
    expect(doc.roles.event.public).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.roles.event.public_serialized).toBe(`ed25519:${doc.roles.event.public}`);
    expect(doc.roles.pack.suite).toBe("ecdsa-p256");
    expect(doc.roles.pack.key_id).toMatch(/^k-[0-9a-f]{16}$/);
    expect(doc.roles.pack.public).toMatch(/^[0-9a-f]{130}$/);
    expect(doc.roles.pack.public_serialized).toBe(`ecdsa-p256:${doc.roles.pack.public}`);
    expect(doc.roles.pack.suites["ecdsa-p256"].public).toBe(doc.roles.pack.public);
    expect(doc.warning).toContain("seeded-dev");
  });
});

describe("the verdict route", () => {
  it("surfaces the full pipeline over an eventless passport", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mintPassport(issuer, "local:demo:verdict-1");
    const response = await serve(issuer, `/passports/${encodeURIComponent(passportId)}/verdict`);
    expect(response.status).toBe(200);
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = (await response.json()) as Record<string, unknown>;
    expect(doc.passport_id).toBe(passportId);
    expect(doc.verified_at).toBeTruthy();
    expect(doc.reading_answered).toBe("current-state");
    expect(doc.as_of).toBeTruthy();

    // The log leg: an eventless log carries no freshness evidence.
    const log = doc.log as Record<string, unknown>;
    expect(log.freshness).toBe("Indeterminate");
    expect(log.outcome).toEqual({ Degraded: "NoFreshnessEvidence" });
    expect(log.reading_answered).toBe("current-state");
    expect(log.trust_marker).toBe("unsigned");
    const crypto = log.cryptographic as Record<string, unknown>;
    expect(crypto.chain_verified).toBe(true);
    expect(crypto.anchor_ok).toBe(null);
    const currentState = log.current_state as Record<string, unknown>;
    expect(currentState.status).toBe("issued");
    expect(currentState.safety).toBe("none");
    expect(currentState.taints).toEqual({ entries: [] });
    const evidentiary = log.evidentiary as Record<string, unknown>;
    expect(evidentiary.events_total).toBe(0);
    expect(evidentiary.as_of).toBe(null);
    expect(evidentiary.coverage).toEqual({ present: [], required: [] });

    // The event-signature audit: no sealed signatures, a real anchor.
    const audit = doc.event_signatures as Record<string, unknown>;
    expect(audit.total).toBe(0);
    expect(audit.verified).toBe(0);
    expect(audit.failures).toEqual([]);
    const anchor = audit.anchor as Record<string, string>;
    expect(anchor.suite).toBe("ed25519");
    expect(anchor.key_id).toMatch(/^k-/);
    expect(anchor.public).toMatch(/^[0-9a-f]{64}$/);

    // The Tier-A carrier leg: minted through the boundary, graded.
    const tierA = doc.tier_a as Record<string, unknown>;
    expect(tierA.grade).toBe("degraded");
    expect(tierA.exit_code).toBe(1);
    expect(tierA.reading_answered).toBe("current-state");
    // The native pipeline: the mint instant is the as-of, aged past
    // the window by the time the verdict runs.
    expect(tierA.freshness).toBe("stale");
    expect(tierA.trust_marker).toBe("attested");
    const findings = tierA.findings as { check: string; grade: string; detail: string }[];
    expect(findings[0]).toEqual({
      check: "schema/decode",
      grade: "Pass",
      detail: "canonical Tier-A framing intact (1 signature slot)",
    });
    expect(findings[1].check).toBe("signature/ecdsa-p256/slot-1");
    expect(findings[1].grade).toBe("Pass");
    expect(findings.map((f) => f.check)).toEqual([
      "schema/decode",
      "signature/ecdsa-p256/slot-1",
      "freshness",
      "evidence/log-head",
      "evidence/validity",
      "status",
      "safety",
    ]);
    const logHead = findings.find((f) => f.check === "evidence/log-head");
    expect(logHead).toEqual({
      check: "evidence/log-head",
      grade: "Degraded",
      detail: "no log-head commitment: the pack cannot anchor the passport's event log",
    });
    const coverage = tierA.coverage as { present: string[]; required: string[] };
    expect(coverage.required).toHaveLength(10);
    expect(coverage.present).toHaveLength(9);
    const carrier = tierA.carrier as Record<string, unknown>;
    expect(carrier.bytes).toBeGreaterThan(0);
    expect(carrier.projected).toBeGreaterThanOrEqual(carrier.bytes as number);
    expect(carrier.qr_version).toBeGreaterThanOrEqual(1);
    const signature = tierA.signature as Record<string, string>;
    expect(signature.suite).toBe("ecdsa-p256");
    expect(signature.key_id).toMatch(/^k-/);
    const readings = tierA.readings as { name: string; grade: string; detail: string }[];
    expect(readings.map((r) => r.name)).toEqual([
      "cryptographic",
      "evidentiary",
      "current-state",
    ]);
    const payload = tierA.payload as Record<string, unknown>;
    expect(payload.status).toBe("issued");
    expect(payload.safety).toBe("none");
    expect(payload.signatures).toBe(1);
    expect(payload.log_head).toBe(null);

    // The config resolution: the DO's mint carries no config vector.
    expect(doc.config).toEqual({ vector: [], resolved: [], unresolved: [] });
  });

  it("replays the DO's events into the verdict legs", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mintPassport(issuer, "local:demo:verdict-2");
    const event = await serve(issuer, `/passports/${encodeURIComponent(passportId)}/events`, {
      method: "POST",
      body: JSON.stringify({
        type: "status-change",
        data: { from: "issued", to: "suspended", authority: "urn:eo:market-surveillance" },
        at: "2026-01-01T00:00:00Z",
      }),
    });
    expect(event.status).toBe(201);
    const response = await serve(issuer, `/passports/${encodeURIComponent(passportId)}/verdict`);
    expect(response.status).toBe(200);
    const doc = (await response.json()) as Record<string, unknown>;
    const log = doc.log as Record<string, unknown>;
    const currentState = log.current_state as Record<string, unknown>;
    expect(currentState.status).toBe("suspended");
    const evidentiary = log.evidentiary as Record<string, unknown>;
    expect(evidentiary.events_total).toBe(1);
    expect(evidentiary.as_of).toBeTruthy();
    // The log leg anchors at the sealed head: the chain verifies, the
    // anchor check passes, the trust marker climbs to log-anchored,
    // and the outcome is a pass at the current-state reading.
    expect(log.outcome).toBe("Pass");
    expect(log.freshness).toEqual({ Fresh: { as_of: "2026-01-01T00:00:00Z" } });
    const crypto = log.cryptographic as { chain_verified: boolean; anchor_ok: boolean | null; head: string | null };
    expect(crypto.chain_verified).toBe(true);
    expect(crypto.anchor_ok).toBe(true);
    expect(crypto.head).toMatch(/^[0-9a-f]{64}$/);
    expect(log.trust_marker).toBe("log-anchored");
    const tierA = doc.tier_a as Record<string, unknown>;
    const payload = tierA.payload as Record<string, unknown>;
    expect(payload.status).toBe("suspended");
    expect(payload.log_head).toBe(crypto.head);
    const findings = tierA.findings as { check: string; grade: string; detail: string }[];
    const logHead = findings.find((f) => f.check === "evidence/log-head");
    expect(logHead?.grade).toBe("Pass");
    expect(logHead?.detail).toContain((crypto.head ?? "").slice(0, 16));
    const status = findings.find((f) => f.check === "status");
    expect(status?.grade).toBe("Degraded");
    expect(status?.detail).toBe("suspended: circulation paused pending resolution");
  });

  it("answers the no-information 404 for unknown passports", async () => {
    const issuer = new IssuerDO(storage());
    const response = await serve(issuer, "/passports/no-such-passport/verdict");
    expect(response.status).toBe(404);
    expect(await response.text()).toBe('{"error":"not found"}');
    expect(response.headers.get("x-as-of")).toBeTruthy();
  });

  it("refuses a bad instant and a bad freshness window", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mintPassport(issuer, "local:demo:verdict-3");
    const base = `/passports/${encodeURIComponent(passportId)}/verdict`;
    const badAt = await serve(issuer, `${base}?at=notatime`);
    expect(badAt.status).toBe(400);
    expect(((await badAt.json()) as Record<string, unknown>).error).toBe(
      "invalid `at` parameter: parse error: timestamp `notatime`: expected at least YYYY-MM-DD",
    );
    const badAge = await serve(issuer, `${base}?max_age=abc`);
    expect(badAge.status).toBe(400);
    expect(((await badAge.json()) as Record<string, unknown>).error).toBe("`max_age` must be a number of seconds");
    const zeroAge = await serve(issuer, `${base}?max_age=0`);
    expect(zeroAge.status).toBe(200);
  });
});

describe("the admin surface", () => {
  it("registers and lists profiles", async () => {
    const issuer = new IssuerDO(storage());
    const missing = await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({ definition: "x" }),
    });
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as Record<string, unknown>).error).toBe("`profile_id` is required");
    const badPoints = await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({ profile_id: "p", definition: "x", data_points: [""] }),
    });
    expect(badPoints.status).toBe(400);
    expect(((await badPoints.json()) as Record<string, unknown>).error).toBe(
      "`data_points` must be an array of non-empty strings",
    );
    const created = await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({
        profile_id: "urn:unidpp:profile:probe",
        definition: "The probe lens",
        version: "2.1.0",
        jurisdiction: "EU",
        data_points: ["unidpp/product-id@1.0.0"],
      }),
    });
    expect(created.status).toBe(201);
    const record = (await created.json()) as Record<string, unknown>;
    expect(record).toMatchObject({
      profile_id: "urn:unidpp:profile:probe",
      definition: "The probe lens",
      version: "2.1.0",
      register_id: null,
      jurisdiction: "EU",
      data_points: ["unidpp/product-id@1.0.0"],
      via: "fixtures",
      detail: "no registry URL configured",
    });
    expect(record.registered_at).toBeTruthy();
    expect(record.audit_seq).toBeGreaterThan(0);
    const duplicate = await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({
        profile_id: "urn:unidpp:profile:probe",
        definition: "The probe lens",
        version: "2.1.0",
      }),
    });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as Record<string, unknown>).error).toBe(
      "profile `urn:unidpp:profile:probe` version `2.1.0` is already registered",
    );
    const listing = await serve(issuer, "/admin/profiles");
    expect(listing.status).toBe(200);
    const doc = (await listing.json()) as { count: number; profiles: unknown[] };
    expect(doc.count).toBe(1);
    expect(doc.profiles).toHaveLength(1);
  });

  it("binds applicability and answers the in-force query", async () => {
    const issuer = new IssuerDO(storage());
    await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({ profile_id: "urn:unidpp:profile:bind", definition: "The lens" }),
    });
    const unknown = await serve(issuer, "/admin/applicability", {
      method: "POST",
      body: JSON.stringify({ profile_id: "absent", product_type: "battery-cells" }),
    });
    expect(unknown.status).toBe(400);
    expect(((await unknown.json()) as Record<string, unknown>).error).toBe("profile `absent` is not registered");
    const inverted = await serve(issuer, "/admin/applicability", {
      method: "POST",
      body: JSON.stringify({
        profile_id: "urn:unidpp:profile:bind",
        product_type: "battery-cells",
        effective_from: "2026-06-01T00:00:00Z",
        effective_until: "2026-01-01T00:00:00Z",
      }),
    });
    expect(inverted.status).toBe(400);
    expect(((await inverted.json()) as Record<string, unknown>).error).toBe(
      "`effective_until` must not precede `effective_from`",
    );
    const bound = await serve(issuer, "/admin/applicability", {
      method: "POST",
      body: JSON.stringify({
        profile_id: "urn:unidpp:profile:bind",
        product_type: "battery-cells",
        effective_from: "2026-01-01T00:00:00Z",
        effective_until: "2027-01-01T00:00:00Z",
        retroactive: true,
      }),
    });
    expect(bound.status).toBe(201);
    const binding = (await bound.json()) as Record<string, unknown>;
    expect(binding).toMatchObject({
      profile_id: "urn:unidpp:profile:bind",
      product_type: "battery-cells",
      profile_version: null,
      effective_from: "2026-01-01T00:00:00Z",
      effective_until: "2027-01-01T00:00:00Z",
      retroactive: true,
      via: "fixtures",
    });
    expect(binding.registered_at).toBeTruthy();
    expect(binding.audit_seq).toBeGreaterThan(0);

    const missing = await serve(issuer, "/admin/applicability");
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as Record<string, unknown>).error).toBe("`product_type` is required");
    const inForce = await serve(
      issuer,
      "/admin/applicability?product_type=battery-cells&at=2026-06-01T00:00:00Z",
    );
    expect(inForce.status).toBe(200);
    const query = (await inForce.json()) as {
      product_type: string;
      count: number;
      bindings: Record<string, unknown>[];
    };
    expect(query.product_type).toBe("battery-cells");
    expect(query.count).toBe(1);
    expect(query.bindings[0].retroactive).toBe(true);
    // Past the effective_until the binding is out of force.
    const expired = await serve(
      issuer,
      "/admin/applicability?product_type=battery-cells&at=2027-06-01T00:00:00Z",
    );
    expect(((await expired.json()) as { count: number }).count).toBe(0);
  });

  it("serves the paged audit log in the native op form", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mintPassport(issuer, "local:demo:audit-1");
    await serve(issuer, `/passports/${encodeURIComponent(passportId)}/events`, {
      method: "POST",
      body: JSON.stringify({
        type: "custody-transfer",
        data: { from: "urn:eo:mfg", to: "holder-1", counterparty_signed: true },
      }),
    });
    await serve(issuer, "/admin/profiles", {
      method: "POST",
      body: JSON.stringify({ profile_id: "p1", definition: "The lens" }),
    });
    const response = await serve(issuer, "/admin/log");
    expect(response.status).toBe(200);
    const doc = (await response.json()) as {
      total: number;
      offset: number;
      records: { seq: number; recorded_at: string; op: Record<string, unknown> }[];
    };
    expect(doc.total).toBe(3);
    expect(doc.offset).toBe(0);
    expect(doc.records).toHaveLength(3);
    const [created, appended, registered] = doc.records;
    expect(created.seq).toBe(1);
    expect(created.recorded_at).toBeTruthy();
    const createOp = created.op as {
      CreatePassport: { record: { config: unknown[]; document: Record<string, unknown> } };
    };
    expect(createOp.CreatePassport.record.config).toEqual([]);
    expect(createOp.CreatePassport.record.document.passport_id).toBe(passportId);
    expect((appended.op as Record<string, unknown>).AppendEvent).toBeTruthy();
    expect((registered.op as Record<string, unknown>).RegisterProfile).toBeTruthy();
    // The page walks the journal window.
    const paged = await serve(issuer, "/admin/log?limit=1&offset=1");
    const window = (await paged.json()) as { total: number; offset: number; records: unknown[] };
    expect(window.total).toBe(3);
    expect(window.offset).toBe(1);
    expect(window.records).toHaveLength(1);
  });

  it("guards the admin surface and mutations when a token is set", async () => {
    const issuer = new IssuerDO(storage(), { UNIDPP_ISSUER_ADMIN_TOKEN: "sekrit" });
    const denied = await serve(issuer, "/admin/profiles");
    expect(denied.status).toBe(401);
    expect(((await denied.json()) as Record<string, unknown>).error).toBe("unauthorized");
    const deniedMint = await serve(issuer, "/passports", {
      method: "POST",
      body: JSON.stringify({ identity: "local:demo:guarded" }),
    });
    expect(deniedMint.status).toBe(401);
    const allowed = await serve(issuer, "/admin/profiles", {
      headers: { authorization: "Bearer sekrit" },
    });
    expect(allowed.status).toBe(200);
    // The bearer token opens the mutation; the pack mint and the
    // verdict stay public (the native gates neither).
    const minted = await serve(issuer, "/passports", {
      method: "POST",
      headers: { authorization: "Bearer sekrit" },
      body: JSON.stringify({ identity: "local:demo:guarded" }),
    });
    expect(minted.status).toBe(201);
    const passportId = ((await minted.json()) as { passport_id: string }).passport_id;
    const pack = await serve(issuer, `/passports/${encodeURIComponent(passportId)}/pack`, {
      method: "POST",
      body: "{}",
    });
    expect(pack.status).toBe(201);
    const verdict = await serve(issuer, `/passports/${encodeURIComponent(passportId)}/verdict`);
    expect(verdict.status).toBe(200);
    // A tokenless deployment serves open.
    const open = new IssuerDO(storage());
    expect((await serve(open, "/admin/profiles")).status).toBe(200);
  });
});
