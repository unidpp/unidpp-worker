// The issuer on a Durable Object (REARCH R12 S4): passports minted
// through the wasm boundary — the same `Passport::mint` the native
// issuer compiles, included by path — journaled events, point-in-time
// reads. The pack minting and the event signature enforcement ride
// later slices; the journal keeps every event verbatim.

import { journalFor, Journal, JournalOp } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";

export interface PassportRecord {
  document: Record<string, unknown>;
  audit_seq: number;
  /** The bound profile layer (clause 5; the issuer's config
   * vector): id + version + optional effective window, stored
   * verbatim and served beside the document. */
  profiles?: { id: string; version: string; effective_from?: string }[];
}

/** A locally registered profile (admin fixture; the registry holds
 * the authoritative 19135 lifecycle, this record is the issuer-side
 * view the config resolution reads). */
export interface IssuerProfileRecord {
  profile_id: string;
  definition: string;
  version: string;
  register_id: string | null;
  jurisdiction: string | null;
  data_points: string[];
  registered_at: string;
}

/** A locally recorded applicability binding (profile ↔ product
 * type), mirroring the registry's binding shape. */
export interface BindingRecord {
  profile_id: string;
  product_type: string;
  profile_version: string | null;
  effective_from: string;
  effective_until: string | null;
  retroactive: boolean;
  registered_at: string;
}

/** One record of the append-only audit log the admin surface serves. */
interface AuditRecord {
  seq: number;
  recorded_at: string;
  op: Record<string, unknown>;
}

const badRequest = (error: string): Response =>
  stamped(400, { error });

const stamped = (status: number, body: Record<string, unknown>): Response =>
  new Response(JSON.stringify({ as_of: isoNow(), ...body }), {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": isoNow(),
    },
  });

// The no-information 404 (I12): byte-identical for every unknown
// passport, no as-of body field.
const notFound = (): Response =>
  new Response(JSON.stringify({ error: "not found" }), {
    status: 404,
    headers: {
      "content-type": "application/json",
      "x-as-of": isoNow(),
    },
  });

const isoNow = (): string =>
  new Date().toISOString();

// The timestamp display: sub-second precision only when the instant
// carries it (the native Timestamp drops zero fractions).
const isoOf = (date: Date): string =>
  date.getUTCMilliseconds() === 0
    ? date.toISOString().replace(/\.\d{3}Z$/, "Z")
    : date.toISOString();

// The point-in-time query instant: `at` (alias `asof`), RFC 3339 —
// the native's parse error text, mirrored for the garbage case.
const parseAt = (params: URLSearchParams): { at: Date | null } | { invalid: string } => {
  const raw = params.get("at") ?? params.get("asof");
  if (raw === null || raw.trim() === "") return { at: null };
  if (!/^\d{4}-\d{2}-\d{2}([Tt ]|$)/.test(raw) || Number.isNaN(Date.parse(raw))) {
    return { invalid: raw };
  }
  return { at: new Date(raw) };
};

// The mint through the wasm boundary: the same source the native
// issuer compiles. The document rides the module's error buffer
// (64 KiB budget); the length pointer reports the real size.
function mintDocument(
  core: CoreExports,
  identity: string,
  capability: string,
  validFromSecs: number,
): { ok: true; document: Record<string, unknown> } | { ok: false; error: string } {
  const encoder = new TextEncoder();
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = encoder.encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const id = put(identity);
  const granularity = put("");
  const cap = put(capability);
  const pid = put("");
  const errPtr = core.unidpp_alloc(1024);
  const lenPtr = core.unidpp_alloc(4);
  const rc = core.unidpp_mint_passport(
    id.ptr,
    id.len,
    granularity.ptr,
    granularity.len,
    cap.ptr,
    cap.len,
    pid.ptr,
    pid.len,
    BigInt(validFromSecs),
    lenPtr,
    errPtr,
  );
  if (rc !== 0) {
    const message = new TextDecoder().decode(
      new Uint8Array(core.memory.buffer, errPtr, 1024).slice().filter((b) => b !== 0),
    );
    return { ok: false, error: message || `the mint failed (${rc})` };
  }
  const length = Number(new DataView(core.memory.buffer, lenPtr).getUint32(0, true));
  const documentText = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, errPtr, length).slice(),
  );
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(documentText) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "the minted document is not JSON" };
  }
  return { ok: true, document };
}

// The pack signing seed: the deployment's issuer seed (32 hex chars
// → 32 bytes) or the deterministic dev seed — the same degrade the
// estate's other operators carry.
function packSeed(core: CoreExports, envSeed: string | undefined): Uint8Array {
  const unhex = (hex: string): Uint8Array =>
    new Uint8Array((hex.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return unhex(envSeed.trim());
  }
  // The native dev label — the same bytes the native keyring derives
  // its pack keys from, so the packs' anchors agree with the native
  // estate's byte for byte.
  return new TextEncoder().encode("unidpp-issuer/pack|unidpp-issuer/dev-1");
}

function mintPackDocument(
  core: CoreExports,
  document: Record<string, unknown>,
  seed: Uint8Array,
  suites: string,
): { ok: true; pack: Record<string, unknown> } | { ok: false; error: string } {
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = new TextEncoder().encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const passport = put(JSON.stringify(document));
  const suitesText = put(suites);
  const seedPtr = core.unidpp_alloc(seed.length);
  new Uint8Array(core.memory.buffer, seedPtr, seed.length).set(seed);
  const rc = core.unidpp_mint_pack(
    passport.ptr,
    passport.len,
    seedPtr,
    seed.length,
    suitesText.ptr,
    suitesText.len,
  );
  [passport, suitesText].forEach((part, i) =>
    core.unidpp_free(part.ptr, [passport.len, suitesText.len][i]),
  );
  core.unidpp_free(seedPtr, seed.length);
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  if (rc !== 0) return { ok: false, error: note || `the pack mint failed (${rc})` };
  try {
    return { ok: true, pack: JSON.parse(note) as Record<string, unknown> };
  } catch {
    return { ok: false, error: "the pack document is not JSON" };
  }
}

export class IssuerDO {
  private passports = new Map<string, PassportRecord>();
  private events: JournalOp[] = [];
  private profiles: IssuerProfileRecord[] = [];
  private bindings: BindingRecord[] = [];
  private audit: AuditRecord[] = [];
  private journal: Journal;
  private core: CoreExports;
  private loaded = false;

  constructor(
    stateOrStorage: unknown,
    private readonly env: Record<string, string | undefined> = {},
  ) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      const ops = await this.journal.all();
      ops.forEach((op, index) => this.apply(op, index + 1));
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") return stamped(200, { status: "ok" });
    // The module root: the discovery document the native serves at
    // the bare prefix (the estate router forwards GET /issuer here).
    if (path === "/" && request.method === "GET") return this.discovery();
    if (path === "/keyring" && request.method === "GET") return this.keyring();
    if (path === "/passports" && request.method === "POST") return this.mint(request);
    if (path === "/passports" && request.method === "GET") return this.list();
    const event = path.match(/^\/passports\/([^/]+)\/events$/);
    if (event && request.method === "POST") {
      return this.appendEvent(request, decodeURIComponent(event[1]));
    }
    const pack = path.match(/^\/passports\/([^/]+)\/pack$/);
    if (pack && request.method === "POST") {
      return this.mintPack(request, decodeURIComponent(pack[1]));
    }
    const verdict = path.match(/^\/passports\/([^/]+)\/verdict$/);
    if (verdict && request.method === "GET") {
      return this.verdict(decodeURIComponent(verdict[1]), url);
    }
    const one = path.match(/^\/passports\/([^/]+)$/);
    if (one && request.method === "GET") return this.getOne(decodeURIComponent(one[1]));
    if (path === "/admin/profiles") {
      if (request.method === "POST") return this.registerProfile(request);
      if (request.method === "GET") return this.listProfiles(request);
    }
    if (path === "/admin/applicability") {
      if (request.method === "POST") return this.bindApplicability(request);
      if (request.method === "GET") return this.applicabilityQuery(request, url);
    }
    if (path === "/admin/log" && request.method === "GET") {
      return this.adminLog(request, url);
    }
    return stamped(404, { error: "no such path" });
  }

  private apply(op: JournalOp, seq: number): void {
    if (op.op === "register-passport") {
      const record = op.record as PassportRecord;
      this.passports.set(record.document.passport_id as string, record);
    } else if (op.op === "append-event") {
      const record = this.passports.get(op.passport_id as string);
      if (record) {
        // The sealed form carries the whole appended log (the seal
        // boundary's output); the legacy journal form carried the bare
        // event object under `events` — a field the document grammar
        // never parsed.
        if (op.sealed !== undefined) {
          record.document.log = op.sealed;
          if (op.signature) {
            const signatures =
              (record.document.event_signatures as unknown[] | undefined) ?? [];
            record.document.event_signatures = [...signatures, op.signature];
          }
        } else {
          const events = (record.document.events as unknown[] | undefined) ?? [];
          record.document.events = [...events, op.event];
        }
      }
      this.events.push(op);
    } else if (op.op === "register-profile") {
      this.profiles.push(op.record as IssuerProfileRecord);
    } else if (op.op === "bind-applicability") {
      this.bindings.push(op.record as BindingRecord);
    }
    // The audit view: every mutation, in journal order — the native's
    // externally-tagged op enum is the wire form.
    const auditOp = this.auditOpOf(op);
    if (auditOp) {
      this.audit.push({ seq, recorded_at: isoNow(), op: auditOp });
    }
  }

  // The audit op for the admin log, in the native enum's serde form
  // (externally tagged); unknown ops ride unnamed (the journal keeps
  // every op verbatim, the audit view states the mutations it knows).
  private auditOpOf(op: JournalOp): Record<string, unknown> | null {
    if (op.op === "register-passport") {
      const record = op.record as PassportRecord;
      // The audit record is a snapshot: the document keeps growing
      // (events append) while the audit stays at the recorded instant.
      return {
        CreatePassport: {
          record: {
            config: [],
            document: JSON.parse(JSON.stringify(record.document)) as Record<string, unknown>,
          },
        },
      };
    }
    if (op.op === "append-event") {
      const sealed = (op.sealed as { sealed?: { event: unknown }[] } | undefined)?.sealed;
      const event = sealed?.[sealed.length - 1]?.event ?? op.event;
      return {
        AppendEvent: {
          passport_id: op.passport_id,
          event,
          signature: op.signature ?? null,
        },
      };
    }
    if (op.op === "register-profile") {
      return {
        RegisterProfile: { profile: op.record, via: op.via ?? "fixtures" },
      };
    }
    if (op.op === "bind-applicability") {
      return {
        BindApplicability: { binding: op.record, via: op.via ?? "fixtures" },
      };
    }
    return null;
  }

  private async mint(request: Request): Promise<Response> {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const identity = (v.identity as string)?.trim();
    if (!identity) return badRequest("`identity` is required");
    const capability = (v.capability as string)?.trim() || "silent";
    const validFrom = typeof v.valid_from === "string" ? Date.parse(v.valid_from) : Date.now();
    // The profile layer binds verbatim (the issuer's config
    // vector); the entries must state id and version.
    const rawProfiles = Array.isArray(v.profiles) ? (v.profiles as Record<string, unknown>[]) : [];
    const profiles: NonNullable<PassportRecord["profiles"]> = [];
    for (const entry of rawProfiles) {
      const id = typeof entry["id"] === "string" ? entry["id"].trim() : "";
      const profileVersion = typeof entry["version"] === "string" ? entry["version"].trim() : "";
      if (!id || !profileVersion) {
        return badRequest("each bound profile states `id` and `version`");
      }
      const effectiveFrom = typeof entry["effective_from"] === "string" ? entry["effective_from"] : undefined;
      profiles.push({ id, version: profileVersion, ...(effectiveFrom ? { effective_from: effectiveFrom } : {}) });
    }
    const minted = mintDocument(
      this.core,
      identity,
      capability,
      // The wasm boundary carries no wall clock: the DO supplies it
      // always (SystemTime::now aborts on wasm32-unknown-unknown).
      Math.floor(validFrom / 1000),
    );
    if (!minted.ok) return badRequest(minted.error);
    const passportId = minted.document.passport_id as string;
    if (this.passports.has(passportId)) {
      return badRequest(`passport \`${passportId}\` already exists`);
    }
    const record: PassportRecord = {
      document: minted.document,
      audit_seq: 0,
      ...(profiles.length > 0 ? { profiles } : {}),
    };
    const seq = await this.journal.append({ op: "register-passport", record });
    record.audit_seq = seq;
    this.apply({ op: "register-passport", record }, seq);
    return stamped(201, { ...record.document, audit_seq: seq });
  }

  private async appendEvent(request: Request, passportId: string): Promise<Response> {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const record = this.passports.get(passportId);
    if (!record) return stamped(404, { error: `no passport \`${passportId}\`` });
    // The seal boundary: the native intake — the typed construction,
    // the transition checks, the hash-chained append into the
    // passport's log, the ArtifactEvent signature under the event
    // key. The boundary carries no wall clock: the DO supplies now.
    const seal = eventSeal(
      this.core,
      v,
      {
        log: record.document.log,
        passport_id: passportId,
        eo_id: record.document.eo_id,
        now: Math.floor(Date.now() / 1000),
      },
      eventSeedMaterial(this.core, (this.env as { UNIDPP_ISSUER_SIGN_SEED?: string } | undefined)?.UNIDPP_ISSUER_SIGN_SEED),
    );
    if (!seal.ok) return stamped(seal.status, { error: seal.error });
    const out = seal.out;
    const op: JournalOp = {
      op: "append-event",
      passport_id: passportId,
      sealed: out.log,
      signature: out.signature,
    };
    const seq = await this.journal.append(op);
    this.apply(op, seq);
    return stamped(201, {
      passport_id: passportId,
      seq: out.seq,
      event_type: out.event_type,
      occurred_at: out.occurred_at,
      actor_id: out.actor_id,
      actor_role: out.actor_role,
      trust: out.trust,
      signature: out.signature,
      log_head: out.head,
      status: out.status,
      safety: out.safety,
      audit_seq: record.audit_seq,
    });
  }

  private async mintPack(request: Request, passportId: string): Promise<Response> {
    const record = this.passports.get(passportId);
    if (!record) return stamped(404, { error: `no passport \`${passportId}\`` });
    let v: Record<string, unknown> = {};
    try {
      const text = await request.text();
      if (text.trim()) v = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const suites = typeof (v.suites ?? v.suite) === "string" ? String(v.suites ?? v.suite) : "";
    const minted = mintPackDocument(
      this.core,
      record.document,
      packSeed(this.core, (this.env as { UNIDPP_ISSUER_SIGN_SEED?: string } | undefined)?.UNIDPP_ISSUER_SIGN_SEED),
      suites,
    );
    if (!minted.ok) return badRequest(minted.error);
    return stamped(201, { ...minted.pack, passport_id: passportId });
  }

  private getOne(passportId: string): Response {
    const record = this.passports.get(passportId);
    if (!record) return stamped(404, { error: `no passport \`${passportId}\`` });
    return stamped(200, {
      ...record.document,
      audit_seq: record.audit_seq,
      ...(record.profiles ? { profiles: record.profiles } : {}),
    });
  }

  private list(): Response {
    const passports = [...this.passports.values()].map((record) => ({
      passport_id: record.document.passport_id,
      subject: record.document.product_id,
      audit_seq: record.audit_seq,
    }));
    return stamped(200, { count: passports.length, passports });
  }

  // The operator guard (the native's require_admin): mutations and
  // the admin surface require the deployment's bearer token when one
  // is configured; an unconfigured deployment serves open.
  private adminGuard(request: Request): Response | null {
    const token = this.env.UNIDPP_ISSUER_ADMIN_TOKEN;
    if (!token) return null;
    const presented = request.headers.get("authorization");
    if (presented !== `Bearer ${token}`) {
      return stamped(401, { error: "unauthorized" });
    }
    return null;
  }

  // The discovery document: the service identity, the endpoint index
  // and the deployment posture, exactly the bare-prefix answer of the
  // native module.
  private discovery(): Response {
    return stamped(200, {
      service: "unidpp-issuer",
      version: "0.1.0",
      build_id: "dev",
      description:
        "UniDPP passport lifecycle issuer service: create passports, append server-signed typed events, mint Tier-A packs with real signatures, run full-pipeline verdicts",
      endpoints: {
        create_passport: "POST /passports",
        list_passports: "GET /passports",
        append_event: "POST /passports/{id}/events",
        mint_pack: "POST /passports/{id}/pack",
        passport: "GET /passports/{id}?at=",
        verdict: "GET /passports/{id}/verdict?at=&max_age=",
        keyring: "GET /keyring",
        register_profile: "POST /admin/profiles",
        list_profiles: "GET /admin/profiles",
        bind_applicability: "POST /admin/applicability",
        applicability: "GET /admin/applicability?product_type=&at=",
        audit_log: "GET /admin/log?limit=&offset=",
        health: "GET /healthz",
      },
      keyring_mode: "seeded-dev",
      signatures: {
        events: "ed25519 (SIGNATIF infrastructure suite)",
        packs: "ecdsa-p256 (configurable via UNIDPP_ISSUER_PACK_SUITE or per-request `suite`; multiple suites co-sign one pack body)",
      },
      auth: "mutations require a Bearer token when UNIDPP_ISSUER_ADMIN_TOKEN is set",
      registry: null,
    });
  }

  // The keyring document (the native's issuer_keyring): the event
  // anchor and the pack roles derived through the same wasm boundary
  // /pack rides — the pack roles come from a mint over a synthetic
  // passport (the framing does not touch the derivation; the keys
  // come from the seed).
  private keyring(): Response {
    const env = this.env as { UNIDPP_ISSUER_SIGN_SEED?: string } | undefined;
    const minted = mintDocument(this.core, "local:unidpp:keyring", "S0", 0);
    if (!minted.ok) return badRequest(minted.error);
    const packMint = mintPackDocument(
      this.core,
      minted.document,
      packSeed(this.core, env?.UNIDPP_ISSUER_SIGN_SEED),
      "",
    );
    if (!packMint.ok) return badRequest(`pack signing: ${packMint.error}`);
    const pack = packMint.pack as {
      signatures: { suite: string; key_id: string; anchor: string }[];
      anchors: Record<string, string>;
    };
    const slots = pack.signatures ?? [];
    const suiteEntries: Record<string, unknown> = {};
    for (const slot of slots) {
      const publicHex = (pack.anchors[slot.suite] ?? slot.anchor ?? "").toLowerCase();
      suiteEntries[slot.suite] = {
        suite: slot.suite,
        key_id: slot.key_id,
        public: publicHex,
        public_serialized: `${slot.suite}:${publicHex}`,
      };
    }
    const event = eventAnchor(this.core, env?.UNIDPP_ISSUER_SIGN_SEED);
    const first = slots[0];
    return stamped(200, {
      dev_seed: "unidpp-issuer/dev-1",
      mode: "seeded-dev",
      roles: {
        event: {
          suite: event.suite,
          key_id: event.key_id,
          public: event.public,
          public_serialized: `ed25519:${event.public}`,
        },
        pack: first
          ? {
              suite: first.suite,
              key_id: first.key_id,
              public: (pack.anchors[first.suite] ?? first.anchor ?? "").toLowerCase(),
              public_serialized: `${first.suite}:${(pack.anchors[first.suite] ?? first.anchor ?? "").toLowerCase()}`,
              suites: suiteEntries,
            }
          : { suites: suiteEntries },
      },
      warning:
        "seeded-dev mode is for development only; production deployments must use env-key mode",
    });
  }

  // The full-pipeline verdict (the native's passport_verdict): the
  // log verdict over the passport's own events, the event-signature
  // audit against the keyring anchor, the Tier-A carrier leg (minted
  // through the same wasm boundary /pack rides) and the config
  // resolution.
  private verdict(passportId: string, url: URL): Response {
    const at = parseAt(url.searchParams);
    if ("invalid" in at) {
      return badRequest(
        `invalid \`at\` parameter: parse error: timestamp \`${at.invalid}\`: expected at least YYYY-MM-DD`,
      );
    }
    const maxAgeRaw = url.searchParams.get("max_age");
    const maxAge = maxAgeRaw === null || maxAgeRaw.trim() === ""
      ? Number(this.env.UNIDPP_ISSUER_MAX_AGE ?? "") || 86_400
      : /^\d+$/.test(maxAgeRaw.trim())
        ? Number(maxAgeRaw)
        : Number.NaN;
    if (Number.isNaN(maxAge)) {
      return badRequest("`max_age` must be a number of seconds");
    }
    const record = this.passports.get(passportId);
    if (!record) return notFound();
    const now = at.at ?? new Date();
    const nowMs = now.getTime();

    const log = logVerdictLeg(this.core, record, nowMs);
    const eventAudit = eventSignatureAudit(this.core, record, this.env);
    const leg = tierAVerdictLeg(this.core, record, this.env, nowMs, maxAge);
    if ("response" in leg) return leg.response;
    return stamped(200, {
      passport_id: passportId,
      verified_at: now.toISOString(),
      reading_answered: "current-state",
      log,
      event_signatures: eventAudit,
      tier_a: leg.leg,
      config: { vector: [], resolved: [], unresolved: [] },
    });
  }

  // Register a profile locally (the fixtures fallback of the native's
  // forwarding: the DO records and serves it, the estate's registry DO
  // holds the authoritative register).
  private async registerProfile(request: Request): Promise<Response> {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const profileId = reqStr(v, "profile_id");
    if (profileId === null) return badRequest("`profile_id` is required");
    const definition = reqStr(v, "definition");
    if (definition === null) return badRequest("`definition` is required");
    const version = optStr(v, "version") ?? "1.0.0";
    const registerId = optStr(v, "register_id") ?? null;
    const jurisdiction = optStr(v, "jurisdiction") ?? null;
    const dataPoints: string[] = [];
    if (v["data_points"] !== undefined && v["data_points"] !== null) {
      if (!Array.isArray(v["data_points"])) {
        return badRequest("`data_points` must be an array of strings");
      }
      for (const item of v["data_points"] as unknown[]) {
        if (typeof item !== "string" || !item.trim()) {
          return badRequest("`data_points` must be an array of non-empty strings");
        }
        dataPoints.push(item.trim());
      }
    }
    if (
      this.profiles.some((p) => p.profile_id === profileId && p.version === version)
    ) {
      return stamped(409, {
        error: `profile \`${profileId}\` version \`${version}\` is already registered`,
      });
    }
    const record: IssuerProfileRecord = {
      profile_id: profileId,
      definition,
      version,
      register_id: registerId,
      jurisdiction,
      data_points: dataPoints,
      registered_at: isoNow(),
    };
    const op: JournalOp = { op: "register-profile", record, via: "fixtures" };
    const seq = await this.journal.append(op);
    this.apply(op, seq);
    return stamped(201, {
      ...record,
      via: "fixtures",
      detail: "no registry URL configured",
      audit_seq: seq,
    });
  }

  private listProfiles(request: Request): Response {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    return stamped(200, {
      count: this.profiles.length,
      profiles: this.profiles,
    });
  }

  // Bind a profile to a product type (the local record of the
  // registry's binding shape; the profile must be registered here).
  private async bindApplicability(request: Request): Promise<Response> {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const profileId = reqStr(v, "profile_id");
    if (profileId === null) return badRequest("`profile_id` is required");
    const productType = reqStr(v, "product_type");
    if (productType === null) return badRequest("`product_type` is required");
    const profileVersion = optStr(v, "profile_version") ?? null;
    const nowMs = Date.now();
    const parsedFrom = optTimestamp(v, "effective_from");
    if ("invalid" in parsedFrom) {
      return badRequest(
        `effective_from: parse error: timestamp \`${parsedFrom.invalid}\`: expected at least YYYY-MM-DD`,
      );
    }
    const effectiveFrom = parsedFrom.at ?? new Date(nowMs);
    const parsedUntil = optTimestamp(v, "effective_until");
    if ("invalid" in parsedUntil) {
      return badRequest(
        `effective_until: parse error: timestamp \`${parsedUntil.invalid}\`: expected at least YYYY-MM-DD`,
      );
    }
    const effectiveUntil = parsedUntil.at;
    if (effectiveUntil && effectiveUntil.getTime() < effectiveFrom.getTime()) {
      return badRequest("`effective_until` must not precede `effective_from`");
    }
    const retroactive = v["retroactive"] === undefined || v["retroactive"] === null
      ? false
      : typeof v["retroactive"] === "boolean"
        ? (v["retroactive"] as boolean)
        : undefined;
    if (retroactive === undefined) {
      return badRequest("`retroactive` must be a boolean");
    }
    if (!this.profiles.some((p) => p.profile_id === profileId)) {
      return badRequest(`profile \`${profileId}\` is not registered`);
    }
    const record: BindingRecord = {
      profile_id: profileId,
      product_type: productType,
      profile_version: profileVersion,
      effective_from: isoOf(effectiveFrom),
      effective_until: effectiveUntil ? isoOf(effectiveUntil) : null,
      retroactive,
      registered_at: isoOf(new Date(nowMs)),
    };
    const op: JournalOp = { op: "bind-applicability", record, via: "fixtures" };
    const seq = await this.journal.append(op);
    this.apply(op, seq);
    return stamped(201, {
      ...record,
      via: "fixtures",
      detail: "no registry URL configured",
      audit_seq: seq,
    });
  }

  // The applicability bindings in force for a product type at an
  // instant (legal as-of semantics: a retroactive binding applies from
  // its effective_from, a non-retroactive one from its registration).
  private applicabilityQuery(request: Request, url: URL): Response {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    const at = parseAt(url.searchParams);
    if ("invalid" in at) {
      return badRequest(
        `invalid \`at\` parameter: parse error: timestamp \`${at.invalid}\`: expected at least YYYY-MM-DD`,
      );
    }
    const asOf = at.at ?? new Date();
    const subject = url.searchParams.get("product_type")?.trim();
    if (!subject) return badRequest("`product_type` is required");
    const inForce = this.bindings.filter(
      (b) => b.product_type === subject && bindingAppliesAt(b, asOf),
    );
    return stamped(200, {
      product_type: subject,
      count: inForce.length,
      bindings: inForce,
    });
  }

  // The append-only audit log, paged (default 100 records, hard cap
  // 10 000; an unparseable page falls back to the default, the same
  // tolerance the native parser carries).
  private adminLog(request: Request, url: URL): Response {
    const guard = this.adminGuard(request);
    if (guard) return guard;
    const limitRaw = url.searchParams.get("limit");
    const limit = limitRaw && /^\d+$/.test(limitRaw)
      ? Math.min(Number(limitRaw), 10_000)
      : 100;
    const offsetRaw = url.searchParams.get("offset");
    const offset = offsetRaw && /^\d+$/.test(offsetRaw) ? Number(offsetRaw) : 0;
    return stamped(200, {
      total: this.audit.length,
      offset,
      records: this.audit.slice(offset, offset + limit),
    });
  }
}

// ---------------------------------------------------------------------------
// Verdict legs and admin helpers (the native api.rs semantics over the
// DO's own state)
// ---------------------------------------------------------------------------

const reqStr = (v: Record<string, unknown>, key: string): string | null => {
  const value = v[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
};

const optStr = (v: Record<string, unknown>, key: string): string | null => {
  const value = v[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
};

// The event key's seed material: the deployment's env seed (32 raw
// bytes) when set, else the native dev label — the bytes
// `unidpp-issuer/event|unidpp-issuer/dev-1`, the same derivation the
// native keyring runs, so the edge's event signatures verify against
// the native estate's anchors byte for byte.
function eventSeedMaterial(core: CoreExports, envSeed: string | undefined): Uint8Array {
  void core;
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return unhex(envSeed.trim());
  }
  return new TextEncoder().encode("unidpp-issuer/event|unidpp-issuer/dev-1");
}

// The event-seal boundary call: the native intake — the typed
// construction, the transition checks, the hash-chained append into
// the passport's log, the ArtifactEvent signature. The refusal rides
// back as the native text with its status.
function eventSeal(
  core: CoreExports,
  request: Record<string, unknown>,
  state: Record<string, unknown>,
  material: Uint8Array,
): { ok: true; out: Record<string, unknown> } | { ok: false; status: number; error: string } {
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = new TextEncoder().encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const rq = put(JSON.stringify(request));
  const st = put(JSON.stringify(state));
  const seedPtr = core.unidpp_alloc(material.length);
  new Uint8Array(core.memory.buffer, seedPtr, material.length).set(material);
  const lenPtr = core.unidpp_alloc(4);
  const out = core.unidpp_alloc(1048576);
  const rc = core.unidpp_event_seal(
    rq.ptr,
    rq.len,
    st.ptr,
    st.len,
    seedPtr,
    material.length,
    lenPtr,
    out,
    1048576,
  );
  [rq, st].forEach((p) => core.unidpp_free(p.ptr, p.len));
  core.unidpp_free(seedPtr, material.length);
  const len = Number(new DataView(core.memory.buffer, lenPtr).getUint32(0, true));
  const text = new TextDecoder().decode(new Uint8Array(core.memory.buffer, out, len).slice());
  core.unidpp_free(out, 1048576);
  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (rc === 0) return { ok: true, out: parsed };
  return {
    ok: false,
    status: Number(parsed.status ?? 400),
    error: String(parsed.error ?? text),
  };
}

// The canonical body of a stored typed event, through the boundary —
// the bytes an ArtifactEvent signature covers.
function eventBodyHex(core: CoreExports, event: unknown): { ok: true; hex: string } | { ok: false; error: string } {
  const bytes = new TextEncoder().encode(JSON.stringify(event));
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  const rc = core.unidpp_event_body(ptr, bytes.length);
  core.unidpp_free(ptr, bytes.length);
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(0, noteLen)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  if (rc !== 0) return { ok: false, error: note };
  return { ok: true, hex: note };
}

// An optional RFC 3339 body timestamp; the invalid case carries the
// raw token (the native parse error names it).
const optTimestamp = (
  v: Record<string, unknown>,
  key: string,
): { at: Date | null } | { invalid: string } => {
  const value = v[key];
  if (value === undefined || value === null) return { at: null };
  if (typeof value !== "string" || /^\s*$/.test(value)) return { invalid: String(value) };
  if (!/^\d{4}-\d{2}-\d{2}([Tt ]|$)/.test(value) || Number.isNaN(Date.parse(value))) {
    return { invalid: value };
  }
  return { at: new Date(value) };
};

// Whether a binding is in force at an instant: the window applies,
// and a non-retroactive binding only from its registration.
const bindingAppliesAt = (binding: BindingRecord, at: Date): boolean => {
  const from = Date.parse(binding.effective_from);
  if (Number.isFinite(from) && at.getTime() < from) return false;
  if (binding.effective_until) {
    const until = Date.parse(binding.effective_until);
    if (Number.isFinite(until) && at.getTime() > until) return false;
  }
  if (binding.retroactive) return true;
  const registered = Date.parse(binding.registered_at);
  return !Number.isFinite(registered) || at.getTime() >= registered;
};

const hexOf = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

function coreDigest(core: CoreExports, data: Uint8Array): Uint8Array {
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  const digest = out.slice();
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return digest;
}

// The event-signature anchor: a real signatif ed25519 key derived from
// the deployment's event-seed material (the env seed's 32 bytes when
// set, else the deterministic dev digest) through the wasm boundary —
// the same derivation discipline the pack seed carries.
function eventAnchor(
  core: CoreExports,
  envSeed: string | undefined,
): { suite: string; key_id: string; public: string } {
  // The key identity rides the boundary: the same derivation the seal
  // runs (the native keyring's label), so the anchor names the key
  // the signatures carry.
  const material = eventSeedMaterial(core, envSeed);
  const materialPtr = core.unidpp_alloc(material.length);
  new Uint8Array(core.memory.buffer, materialPtr, material.length).set(material);
  const suite = new TextEncoder().encode("ed25519");
  const suitePtr = core.unidpp_alloc(suite.length);
  new Uint8Array(core.memory.buffer, suitePtr, suite.length).set(suite);
  const rc = core.unidpp_key_identity(materialPtr, material.length, suitePtr, suite.length);
  core.unidpp_free(materialPtr, material.length);
  core.unidpp_free(suitePtr, suite.length);
  const notePtr = core.unidpp_alloc(4096);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(0, noteLen)).slice(),
  );
  core.unidpp_free(notePtr, 4096);
  if (rc !== 0) throw new Error("the event key derivation failed");
  return JSON.parse(note) as { suite: string; key_id: string; public: string };
}

// The event-signature self-audit (the verdict's dedicated audit leg:
// ed25519 event signatures ride no carrier slot — the documented
// deviation).
function eventSignatureAudit(
  core: CoreExports,
  record: PassportRecord,
  env: Record<string, string | undefined>,
): Record<string, unknown> {
  const signatures =
    (record.document.event_signatures as
      | { seq: number; suite: string; key_id: string; signature: string }[]
      | undefined) ?? [];
  const sealed =
    ((record.document.log as { sealed?: { event: unknown }[] } | undefined)
      ?.sealed ?? []) as { event: unknown }[];
  const anchor = eventAnchor(core, env.UNIDPP_ISSUER_SIGN_SEED);
  let verified = 0;
  const failures: { seq: number; why: string }[] = [];
  for (const sig of signatures) {
    const entry = sealed[sig.seq];
    const why = (() => {
      if (!entry || (entry.event as { seq?: number })?.seq !== sig.seq) {
        return `signature names seq ${sig.seq} but no such event is sealed`;
      }
      const body = eventBodyHex(core, entry.event);
      if (!body.ok) return `canonical body: ${body.error}`;
      const rc = verifyRaw(
        core,
        "artifact-event",
        sig.suite,
        anchor.public,
        body.hex,
        sig.signature,
      );
      if (rc === null) return `suite \`${sig.suite}\` does not ride the boundary`;
      if (rc !== 1) return "the signature does not verify under the anchor";
      return null;
    })();
    if (why === null) verified += 1;
    else failures.push({ seq: sig.seq, why });
  }
  return {
    total: signatures.length,
    verified,
    failures,
    anchor,
  };
}

// The raw verify call through the boundary (the domain token, the
// suite token, the hex public, the hex payload, the hex signature);
// a suite the boundary carries answers null.
function verifyRaw(
  core: CoreExports,
  domain: string,
  suite: string,
  publicHex: string,
  payloadHex: string,
  signatureHex: string,
): number | null {
  const put = (bytes: Uint8Array): { ptr: number; len: number } => {
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const suiteSizes: Record<string, number> = { ed25519: 32, "ecdsa-p256": 65 };
  const size = suiteSizes[suite];
  if (!size) return null;
  const domainB = put(new TextEncoder().encode(domain));
  const suiteB = put(new TextEncoder().encode(suite));
  const publicB = put(unhex(publicHex));
  const payloadB = put(unhex(payloadHex));
  const sigB = put(unhex(signatureHex));
  const rc = core.unidpp_verify_raw(
    domainB.ptr,
    domainB.len,
    suiteB.ptr,
    suiteB.len,
    publicB.ptr,
    publicB.len,
    payloadB.ptr,
    payloadB.len,
    sigB.ptr,
    sigB.len,
  );
  [domainB, suiteB, publicB, payloadB, sigB].forEach((p) =>
    core.unidpp_free(p.ptr, p.len),
  );
  return rc;
}

// The trust marker ladder (I9) over signing evidence.
const trustMarkerOf = (
  present: number,
  distinctSuites: number,
  attested: boolean,
  anchored: boolean,
): string => {
  if (anchored) return "log-anchored";
  if (distinctSuites >= 2 && present >= 2) return "multi-signed";
  if (attested && present >= 1) return "attested";
  if (present >= 1) return "self-declared";
  return "unsigned";
};

// The graded ladder: 0 pass, 1 degraded, 2 fail — the verdict crate's
// grade order, with its wire tokens.
const GRADE_TOKENS = ["pass", "degraded", "fail"] as const;
const GRADE_WIRE = ["Pass", "Degraded", "Fail"] as const;
type Grade = 0 | 1 | 2;
const worst = (a: Grade, b: Grade): Grade => (a >= b ? a : b);

const STATUS_GRADES: Record<string, Grade> = {
  issued: 0,
  suspended: 1,
  consumed: 1,
  transformed: 1,
  "end-of-waste": 1,
  archived: 1,
  invalidated: 2,
  "non-conformant": 2,
};

const STATUS_DETAILS: Record<string, string> = {
  issued: "issued: in active circulation",
  suspended: "suspended: circulation paused pending resolution",
  consumed: "consumed: input of a transformation, no longer in circulation",
  transformed: "transformed: superseded by derived passports",
  "end-of-waste": "end-of-waste status: waste regime re-entry",
  archived: "archived: lifecycle ended",
  invalidated: "invalidated: not valid for circulation",
  "non-conformant": "non-conformant: failed evaluation",
};

const SAFETY_GRADES: Record<string, Grade> = {
  none: 0,
  "recall-active": 2,
  "security-flagged": 2,
};

const SAFETY_DETAILS: Record<string, string> = {
  none: "no recall or security flag",
  "recall-active": "RECALL ACTIVE: do not release",
  "security-flagged": "SECURITY FLAGGED: do not release",
};

const VALID_STATUS_TOKENS = new Set(Object.keys(STATUS_GRADES));

// The replayed current state of a passport over the DO's verbatim
// events: the status ladder, the custodian, the safety flag, the
// evidentiary counts and the newest event instant.
function replayEvents(
  events: unknown[],
  atMs: number,
): {
  status: string;
  safety: string;
  custodian: string | null;
  corrections: number;
  recalls: number;
  security_flags: number;
  stamps: number;
  events_total: number;
  last_event_at: string | null;
} {
  let status = "issued";
  let custodian: string | null = null;
  let corrections = 0;
  let recalls = 0;
  let securityFlags = 0;
  let stamps = 0;
  let lastEventAt: string | null = null;
  let lastEventMs = Number.NEGATIVE_INFINITY;
  let eventsTotal = 0;
  for (const raw of events) {
    // The sealed form wraps the typed event; the legacy journal form
    // carried the bare event object.
    const outer = (raw ?? {}) as Record<string, unknown>;
    const event = (outer.event ?? outer) as Record<string, unknown>;
    const payload = event["payload"] as Record<string, unknown> | undefined;
    const type =
      typeof event["event_type"] === "string"
        ? (event["event_type"] as string)
        : typeof event["type"] === "string"
          ? (event["type"] as string)
          : "";
    const statusChange = payload?.["StatusChange"] as Record<string, unknown> | undefined;
    const custody = payload?.["CustodyTransfer"] as Record<string, unknown> | undefined;
    const to =
      (statusChange?.["to"] as string | undefined) ??
      (custody?.["to"] as string | undefined) ??
      (typeof event["to"] === "string" ? (event["to"] as string).trim() : "");
    const occurredAt =
      typeof event["occurred_at"] === "string" ? (event["occurred_at"] as string) : null;
    const occurredMs = occurredAt !== null && !Number.isNaN(Date.parse(occurredAt))
      ? Date.parse(occurredAt)
      : null;
    if (occurredMs !== null && occurredMs > lastEventMs) {
      lastEventMs = occurredMs;
      lastEventAt = occurredAt;
    }
    // The evidentiary prefix: events at or before the verification
    // instant (the native's log.as_of(at)).
    if (occurredMs === null || occurredMs <= atMs) eventsTotal += 1;
    if (
      (type === "status.change" || type === "status-change") &&
      VALID_STATUS_TOKENS.has(to)
    )
      status = to;
    if (type === "custody.transfer" || type === "custody-transfer") {
      if (to) custodian = to;
    }
    if (type === "correction") corrections += 1;
    if (type === "recall.campaign" || type === "recall-campaign") recalls += 1;
    if (type === "flag.security" || type === "flag-security") securityFlags += 1;
    if (type === "inspection.stamp" || type === "inspection-stamp") stamps += 1;
  }
  return {
    status,
    safety: securityFlags > 0 ? "security-flagged" : recalls > 0 ? "recall-active" : "none",
    custodian,
    corrections,
    recalls,
    security_flags: securityFlags,
    stamps,
    events_total: eventsTotal,
    last_event_at: lastEventAt,
  };
}

// The boundary call helper for the verdict-leg exports: JSON in, the
// native leg JSON out (the out buffer doubles as the error note).
function legCall(
  core: CoreExports,
  run: (lenPtr: number, out: number) => number,
): { ok: true; out: Record<string, unknown> } | { ok: false; error: string } {
  const lenPtr = core.unidpp_alloc(4);
  const out = core.unidpp_alloc(1048576);
  const rc = run(lenPtr, out);
  const len = Number(new DataView(core.memory.buffer, lenPtr).getUint32(0, true));
  let text = "";
  if (rc !== 0) {
    const notePtr = core.unidpp_alloc(1048576);
    const noteLen = core.unidpp_note_take(notePtr);
    text = new TextDecoder().decode(
      new Uint8Array(core.memory.buffer, notePtr, Math.max(0, noteLen)).slice(),
    );
    core.unidpp_free(notePtr, 1048576);
    core.unidpp_free(lenPtr, 4);
    core.unidpp_free(out, 1048576);
    return { ok: false, error: text || `the leg failed (${rc})` };
  }
  text = new TextDecoder().decode(new Uint8Array(core.memory.buffer, out, len).slice());
  core.unidpp_free(lenPtr, 4);
  core.unidpp_free(out, 1048576);
  return { ok: true, out: JSON.parse(text) as Record<string, unknown> };
}

// The log verdict leg: the verdict crate's builder through the
// boundary — the native shapes and the native chain logic, not a
// mirror of them.
function logVerdictLeg(
  core: CoreExports,
  record: PassportRecord,
  nowMs: number,
): Record<string, unknown> {
  const signatures =
    (record.document.event_signatures as unknown[] | undefined) ?? [];
  const logText = JSON.stringify(
    record.document.log ?? { subject: record.document.passport_id, sealed: [] },
  );
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = new TextEncoder().encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const log = put(logText);
  const outcome = legCall(core, (lenPtr, out) =>
    core.unidpp_log_verdict(
      log.ptr,
      log.len,
      BigInt(Math.floor(nowMs / 1000)),
      signatures.length > 0 ? 1 : 0,
      lenPtr,
      out,
      1048576,
    ),
  );
  core.unidpp_free(log.ptr, log.len);
  if (!outcome.ok) throw new Error(`the log verdict failed: ${outcome.error}`);
  return outcome.out;
}

// The Tier-A carrier leg: mint over the passport's sealed log, verify
// under the seeded pack anchors, render the graded outcome — the
// native pipeline through the boundary.
function tierAVerdictLeg(
  core: CoreExports,
  record: PassportRecord,
  env: Record<string, string | undefined>,
  nowMs: number,
  maxAge: number,
): { leg: Record<string, unknown> } | { response: Response } {
  const documentText = JSON.stringify(record.document);
  const put = (bytes: Uint8Array): { ptr: number; len: number } => {
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const document = put(new TextEncoder().encode(documentText));
  const seed = packSeed(core, (env as { UNIDPP_ISSUER_SIGN_SEED?: string }).UNIDPP_ISSUER_SIGN_SEED);
  const seedB = put(seed);
  const suites = put(new TextEncoder().encode(""));
  const outcome = legCall(core, (lenPtr, out) =>
    core.unidpp_tier_a_leg(
      document.ptr,
      document.len,
      seedB.ptr,
      seedB.len,
      suites.ptr,
      suites.len,
      BigInt(Math.floor(nowMs / 1000)),
      BigInt(Math.ceil(maxAge)),
      lenPtr,
      out,
      1048576,
    ),
  );
  [document, seedB, suites].forEach((p) => core.unidpp_free(p.ptr, p.len));
  if (!outcome.ok) return { response: badRequest(`pack signing: ${outcome.error}`) };
  return { leg: outcome.out };
}

