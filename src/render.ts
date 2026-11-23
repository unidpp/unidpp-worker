// The render surface on the estate (REARCH R12 S5-serve): the EN 18222
// document and the UNTP verifiable-credential triad, computed through
// the wasm boundary — the same renderers the native gateway compiles.
// The passport rides the estate's own issuer DO; the built-in demo
// passport is the stated fallback (the native fixtures doctrine); the
// profile layer is the issuer's bound profiles (empty while none are
// bound). Unknown ids 404 no-information, identical bytes for unknown
// and deliberately unresolvable (I12). The consumer-facing surfaces
// ride beside the renderings (TODO.impl 224): the report channel
// (journaled, sequenced, receipted; the edge holds the reports in
// module state — the native's in-memory journal, the dev default) and
// the scan-token gate (off unless the deployment configures a policy;
// absent policy the gate is open, public resolution is the default).

import { workerCore } from "./mount";

export interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

// The render module's environment: the estate passes the issuer
// namespace and the tenant; the gateway's deployment keys ride the
// same object when a deployment binds them (UNIDPP_GATEWAY_* — the
// native Config's own names).
export interface RenderEnv {
  ISSUER?: DoNamespace;
  tenant?: string;
  UNIDPP_GATEWAY_ADMIN_TOKEN?: string;
  UNIDPP_GATEWAY_FEEDBACK_RATE?: string;
  UNIDPP_GATEWAY_SCAN_TTL_SECS?: string;
  UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN?: string;
}

const NOTE_CAPACITY = 1048576;

// The no-information 404: identical bytes for unknown passports and
// anything deliberately unresolvable alike (I12) — the native
// NOT_FOUND_BODY.
const NOT_FOUND_BODY = '{"error":"not found"}';

const isoStamp = (): string =>
  new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

const stamped = (status: number, body: string, asOf: string): Response =>
  new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": asOf,
    },
  });

const noInformation = (asOf: string): Response => stamped(404, NOT_FOUND_BODY, asOf);

// A wire-shaped JSON answer: content-type alone, no as-of stamp —
// the receipt, the citation, the listing and the gate's statements
// answer exactly as the native handlers build them.
const wireJson = (status: number, body: unknown, pretty = false): Response =>
  new Response(JSON.stringify(body, null, pretty ? 2 : undefined), {
    status,
    headers: { "content-type": "application/json" },
  });

// The axum method fallback: an empty 405 naming the served method(s).
const methodNotAllowed = (allow: string): Response =>
  new Response(null, { status: 405, headers: { allow } });

// The axum path rejection: a plain-text u64 parse failure.
const pathRejection = (raw: string): Response =>
  new Response(`Invalid URL: Cannot parse \`${raw}\` to a \`u64\``, {
    status: 400,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });

// serde_json's own message for the malformed bodies a report or an
// issuance can carry (the native handlers echo it after their
// wrapper); the deterministic shapes are emulated, anything exotic
// answers the generic value error.
const serdeJsonError = (text: string): string => {
  const t = text.trim();
  if (t === "") return "EOF while parsing a value at line 1 column 0";
  const head = t[0];
  if (head === "n" || head === "t" || head === "f")
    return "expected ident at line 1 column 2";
  return "expected value at line 1 column 1";
};

// ---------------------------------------------------------------------------
// The report channel (the native FeedbackStore, in-memory journal —
// the dev default; the edge has no filesystem to journal onto).
// ---------------------------------------------------------------------------

interface FeedbackRecord {
  seq: number;
  recorded_at: string;
  identifier: string;
  category: string;
  contact: string | null;
  details: string;
}

// The module state: the reports filed in this isolate (the native
// store opens journaled-when-configured; the edge runs in-memory
// only), the per-identifier rate windows and the scan gate's tokens.
const feedbackRecords: FeedbackRecord[] = [];
const feedbackWindows = new Map<string, number[]>();
let scanSeq = 0;
const scanTokens = new Map<string, number>();
const scanWindows = new Map<string, number[]>();

// The typed category: MobileQR's two structured types plus a stated
// free-form other (the `other:` prefix is the wire form of every
// non-exact category, exactly as the native parses then prints it).
const categoryOf = (raw: string): string => {
  const trimmed = raw.trim();
  if (trimmed === "goods-mismatch" || trimmed === "advertising-mismatch") {
    return trimmed;
  }
  return `other:${trimmed}`;
};

// The record's wire form (the keys in the native's sorted order).
const feedbackJson = (
  rec: FeedbackRecord,
  includeContact: boolean,
): Record<string, unknown> => ({
  category: rec.category,
  contact: includeContact ? rec.contact : "withheld",
  details: rec.details,
  identifier: rec.identifier,
  recorded_at: rec.recorded_at,
  seq: rec.seq,
});

// The pluggable admission gate's in-repo implementation: a
// per-identifier sliding window of one minute (the RateLimited
// flavor; unconfigured the gate is permissive).
function admitFeedback(env: RenderEnv, identifier: string): string | null {
  const rate = Number(env.UNIDPP_GATEWAY_FEEDBACK_RATE ?? 0) || 0;
  if (rate <= 0) return null;
  const now = Date.now();
  const window = (feedbackWindows.get(identifier) ?? []).filter(
    (t) => now - t < 60_000,
  );
  if (window.length >= rate) {
    return `rate limit: at most ${rate} report(s) per identifier per minute — refused, retry after the window`;
  }
  window.push(now);
  feedbackWindows.set(identifier, window);
  return null;
}

// ---------------------------------------------------------------------------
// The scan-token gate (the native ScanGate): ephemeral edge state —
// issued tokens and the per-source issuance window. Off unless the
// deployment configures a TTL; off, everything admits and issuance
// states the open gate.
// ---------------------------------------------------------------------------

interface ScanPolicy {
  tokenTtlSecs: number;
  issueLimitPerMinute: number;
}

const scanPolicyOf = (env: RenderEnv): ScanPolicy => ({
  tokenTtlSecs: Number(env.UNIDPP_GATEWAY_SCAN_TTL_SECS ?? 0) || 0,
  issueLimitPerMinute: Number(env.UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN ?? 0) || 0,
});

const scanOn = (policy: ScanPolicy): boolean => policy.tokenTtlSecs > 0;

function scanIssue(
  policy: ScanPolicy,
  source: string,
): { ok: true; token: string; ttl: number } | { ok: false; reason: string; open: boolean } {
  if (!scanOn(policy)) {
    return {
      ok: false,
      reason: "no scan policy is configured — the gate is open, no token needed",
      open: true,
    };
  }
  const now = Date.now();
  const window = (scanWindows.get(source) ?? []).filter((t) => now - t < 60_000);
  if (
    policy.issueLimitPerMinute > 0 &&
    window.length >= policy.issueLimitPerMinute
  ) {
    return {
      ok: false,
      reason: `scan-token issuance limit: at most ${policy.issueLimitPerMinute} per source per minute — refused, retry after the window`,
      open: false,
    };
  }
  window.push(now);
  scanWindows.set(source, window);
  scanSeq += 1;
  const token = `scan-${scanSeq.toString(16).padStart(16, "0")}`;
  // A token with TTL 0 is born expired — the documented way to
  // observe the expiry statement deterministically.
  scanTokens.set(token, now + policy.tokenTtlSecs * 1000);
  return { ok: true, token, ttl: policy.tokenTtlSecs };
}

// Admit a request's token: null admits; a string is the stated
// refusal (absent / unknown / expired — the expiry names the policy).
function scanAdmit(policy: ScanPolicy, request: Request): string | null {
  if (!scanOn(policy)) return null;
  const headerToken = request.headers.get("x-unidpp-scan");
  const bearer = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/, "");
  const presented = headerToken ?? (bearer === "" ? null : bearer);
  if (!presented) {
    return `scan token required: this gateway enforces a ${policy.tokenTtlSecs} s scan policy — obtain one from POST /scan-tokens`;
  }
  const expiresAt = scanTokens.get(presented);
  if (expiresAt === undefined) return "unknown scan token";
  if (Date.now() >= expiresAt) {
    scanTokens.delete(presented);
    return `scan token expired — the policy window is ${policy.tokenTtlSecs} s; obtain a fresh one from POST /scan-tokens`;
  }
  return null;
}

const scanRefusal = (reason: string, tooMany: boolean): Response =>
  wireJson(tooMany ? 429 : 401, { error: reason });

// ---------------------------------------------------------------------------
// The wasm boundary (unchanged): the renderers the native compiles.
// ---------------------------------------------------------------------------

function durationMs(duration: string): number | null {
  const prefix = duration.startsWith("P") ? duration.slice(1) : null;
  if (prefix === null) return null;
  const [dayPart, timePart, extraTime] = prefix.split("T");
  if (extraTime !== undefined) return null;
  const days = dayPart === "" ? "" : dayPart.endsWith("D") ? dayPart.slice(0, -1) : null;
  if (days === null) return null;
  if (days === "" && timePart === undefined) return null;
  if (days !== "" && !/^\d+$/.test(days)) return null;
  let ms = days === "" ? 0 : Number(days) * 86_400_000;
  if (Number.isNaN(ms)) return null;
  let rest = timePart ?? "";
  for (const [suffix, unitMs] of [["H", 3_600_000], ["M", 60_000]] as const) {
    if (rest === "") break;
    const at = rest.indexOf(suffix);
    if (at <= 0) continue;
    const n = rest.slice(0, at);
    if (!/^\d+$/.test(n)) continue;
    const parsed = Number(n);
    if (Number.isNaN(parsed)) return null;
    ms += parsed * unitMs;
    rest = rest.slice(at + 1);
  }
  if (rest.endsWith("S")) {
    const n = rest.slice(0, -1);
    if (n !== "" && /^\d+(\.\d+)?$/.test(n)) {
      const parsed = Number(n);
      if (Number.isNaN(parsed)) return null;
      ms += parsed * 1000;
      rest = "";
    }
  }
  if (rest !== "") return null;
  return ms;
}

function takeNote(core: ReturnType<typeof workerCore>): string {
  const notePtr = core.unidpp_alloc(NOTE_CAPACITY);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, NOTE_CAPACITY);
  return note;
}

function putBytes(
  core: ReturnType<typeof workerCore>,
  text: string,
): { ptr: number; len: number } {
  const bytes = new TextEncoder().encode(text);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function renderBoundary(
  protocol: string,
  passportText: string,
  profilesJson: string,
  representation: string,
  freshness: string,
  origin: string,
  atSecs: number,
): { ok: true; document: string } | { ok: false; error: string } {
  const core = workerCore();
  const parts = [
    putBytes(core, protocol),
    putBytes(core, passportText),
    putBytes(core, profilesJson),
    putBytes(core, representation),
    putBytes(core, freshness),
    putBytes(core, origin),
  ];
  const rc = core.unidpp_render(
    parts[0].ptr,
    parts[0].len,
    parts[1].ptr,
    parts[1].len,
    parts[2].ptr,
    parts[2].len,
    parts[3].ptr,
    parts[3].len,
    parts[4].ptr,
    parts[4].len,
    parts[5].ptr,
    parts[5].len,
    BigInt(Math.floor(atSecs)),
  );
  const note = takeNote(core);
  parts.forEach((part) => core.unidpp_free(part.ptr, 0));
  if (rc === 0) return { ok: true, document: note };
  return { ok: false, error: note || `the render failed (${rc})` };
}

// The ingest outcome (the boundary's single-call logic), stored by
// passport id — the native IngestStore's entries + receipts, keyed
// the same way.
interface IngestedEntry {
  passport: string;
  profiles: { id: string; version: string; effective_from?: string }[];
  receipt: Record<string, unknown>;
}

const ingestedEntries = new Map<string, IngestedEntry>();

function ingestBoundary(
  bodyText: string,
  atSecs: number,
): { ok: true; outcome: Record<string, unknown> } | { ok: false; error: string } {
  const core = workerCore();
  const part = putBytes(core, bodyText);
  const rc = core.unidpp_ingest(part.ptr, part.len, BigInt(Math.floor(atSecs)));
  const note = takeNote(core);
  core.unidpp_free(part.ptr, 0);
  if (rc === 0) return { ok: true, outcome: JSON.parse(note) as Record<string, unknown> };
  return { ok: false, error: note || `the ingest failed (${rc})` };
}

// The issuer's passport document (the audit sequence stripped), or
// null on a miss. The bound profile layer (clause 5) rides beside
// the document and returns separately for the render's profile
// refs.
async function issuerPassport(
  env: RenderEnv,
  passportId: string,
): Promise<{ document: string; profiles: { id: string; version: string; effective_from?: string }[] } | null> {
  if (!env.ISSUER) return null;
  const stub = env.ISSUER.get(
    env.ISSUER.idFromName(env.tenant ? `estate@${env.tenant}` : "estate"),
  );
  const response = await stub.fetch(
    new Request(`https://do.internal/passports/${encodeURIComponent(passportId)}`),
  );
  if (response.status !== 200) return null;
  const body = (await response.json()) as Record<string, unknown>;
  const profiles = Array.isArray(body.profiles)
    ? (body.profiles as { id: string; version: string; effective_from?: string }[])
    : [];
  const document = { ...body };
  delete document.audit_seq;
  delete document.profiles;
  return { document: JSON.stringify(document), profiles };
}

// The issuer's passport whose subject is GS1-keyed under `gtin`
// (the EN 18222 route addresses the key; the estate scans its own
// store — the documented issuer-mode GTIN limitation, scoped).
async function issuerGtin(
  env: RenderEnv,
  gtin: string,
): Promise<{ document: string; profiles: { id: string; version: string; effective_from?: string }[] } | null> {
  if (!env.ISSUER) return null;
  const stub = env.ISSUER.get(
    env.ISSUER.idFromName(env.tenant ? `estate@${env.tenant}` : "estate"),
  );
  const listed = (await (
    await stub.fetch(new Request("https://do.internal/passports"))
  ).json()) as { passports?: { passport_id: string }[] };
  for (const entry of listed.passports ?? []) {
    const found = await issuerPassport(env, entry.passport_id);
    if (!found) continue;
    // The document's subject serializes through the model's Display:
    // the GS1 family prints as the element string `01+<key>` (with
    // optional `+10+lot` / `+21+serial` tails), everything else as
    // `scheme:key`. The EN route addresses the GTIN key.
    const document = JSON.parse(found.document) as { product_id?: string };
    const subject = document.product_id ?? "";
    if (!subject.startsWith("01+")) continue;
    const key = subject.split("+")[1] ?? "";
    if (key === gtin) return found;
  }
  return null;
}

// The built-in demo passport (the fixtures module's own), or null.
function fixturePassport(): string | null {
  const core = workerCore();
  if (core.unidpp_fixture_passport() !== 0) return null;
  return takeNote(core);
}

export async function render(
  pathname: string,
  request: Request,
  env: RenderEnv,
): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const asOf = isoStamp();
  const atSecs = Math.floor(Date.now() / 1000);

  // GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed
  const en = pathname.match(/^\/en18222\/v1\/dppsByProductId\/([^/]+)$/);
  if (en) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed("GET,HEAD");
    }
    const gate = scanAdmit(scanPolicyOf(env), request);
    if (gate) return scanRefusal(gate, false);
    const gtin = decodeURIComponent(en[1]);
    const representation = (params.get("representation") ?? "").trim();
    if (!["", "full", "compressed"].includes(representation)) {
      return stamped(400, JSON.stringify({ error: `unknown representation \`${representation}\` (expected full|compressed)` }), asOf);
    }
    // The GTIN route addresses the key: only a GS1-keyed passport in
    // the issuer's store resolves (no fixture carries a GTIN subject;
    // anything else is the no-information 404).
    const found = await issuerGtin(env, gtin);
    if (!found) return noInformation(asOf);
    const minted = renderBoundary(
      "en18222",
      found.document,
      JSON.stringify(found.profiles),
      representation,
      "",
      "issuer",
      atSecs,
    );
    if (!minted.ok) return stamped(502, JSON.stringify({ error: minted.error }), asOf);
    return stamped(200, minted.document, asOf);
  }

  // GET /untp/product/{id}?freshness=PnDTnHnMnS
  const untp = pathname.match(/^\/untp\/product\/([^/]+)$/);
  if (untp) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed("GET,HEAD");
    }
    const gate = scanAdmit(scanPolicyOf(env), request);
    if (gate) return scanRefusal(gate, false);
    const id = decodeURIComponent(untp[1]);
    const freshness = (params.get("freshness") ?? "").trim();
    if (freshness && durationMs(freshness) === null) {
      return stamped(400, JSON.stringify({ error: "`freshness` must be an ISO 8601 duration (PnDTnHnMnS)" }), asOf);
    }
    // The native resolution order: the issuer upstream, then the
    // fixture, then the ingested store.
    let found = await issuerPassport(env, id);
    let origin = "issuer";
    let profiles: { id: string; version: string; effective_from?: string }[] = [];
    if (!found) {
      const fixture = fixturePassport();
      const fixtureId = fixture
        ? (JSON.parse(fixture) as { passport_id?: string }).passport_id
        : null;
      if (fixture && fixtureId === id) {
        found = { document: fixture, profiles: [] };
        origin = "fixture";
      }
    }
    if (!found) {
      const ingested = ingestedEntries.get(id);
      if (ingested) {
        found = { document: ingested.passport, profiles: ingested.profiles };
        origin = "fixture";
      }
    }
    if (!found) return noInformation(asOf);
    const minted = renderBoundary(
      "untp",
      found.document,
      JSON.stringify(found.profiles),
      "",
      freshness,
      origin,
      atSecs,
    );
    if (!minted.ok) return stamped(502, JSON.stringify({ error: minted.error }), asOf);
    return stamped(200, minted.document, asOf);
  }

  // POST /untp/ingest — the import direction: a UNTP passport VC
  // (bare, or wrapped in the triad this gateway itself renders) mints
  // a core passport with a deterministic identity through the
  // boundary; conformity credentials land as profile bindings.
  // Idempotent per subject identity; the store is isolate state.
  if (pathname === "/untp/ingest") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    const bodyText = await request.text();
    const outcome = ingestBoundary(bodyText, atSecs);
    if (!outcome.ok) {
      return stamped(
        422,
        JSON.stringify({ status: "degraded", reason: outcome.error }),
        asOf,
      );
    }
    const o = outcome.outcome;
    const passportId = o.passport_id as string;
    const existing = ingestedEntries.get(passportId);
    if (existing) {
      return stamped(
        200,
        JSON.stringify({
          status: "matched",
          passport_id: passportId,
          identity: o.identity,
          granularity: o.granularity,
          profiles: existing.profiles.map((profile) => ({
            id: profile.id,
            version: profile.version,
            effective_from: profile.effective_from ?? null,
          })),
          receipt: existing.receipt,
        }),
        asOf,
      );
    }
    const entry: IngestedEntry = {
      passport: JSON.stringify(o.passport),
      profiles: (o.profiles as { id: string; version: string; effective_from?: string }[]).map(
        (profile) => ({
          id: profile.id,
          version: profile.version,
          ...(profile.effective_from ? { effective_from: profile.effective_from } : {}),
        }),
      ),
      receipt: o.receipt as Record<string, unknown>,
    };
    ingestedEntries.set(passportId, entry);
    return stamped(
      201,
      JSON.stringify({
        status: "imported",
        passport_id: passportId,
        identity: o.identity,
        granularity: o.granularity,
        profiles: entry.profiles.map((profile) => ({
          id: profile.id,
          version: profile.version,
          effective_from: profile.effective_from ?? null,
        })),
        receipt: entry.receipt,
      }),
      asOf,
    );
  }

  // POST /feedback — the consumer report channel: typed, journaled,
  // receipted; admission control decides what a flood is.
  if (pathname === "/feedback") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    const bodyText = await request.text();
    let v: Record<string, unknown>;
    try {
      v = JSON.parse(bodyText) as Record<string, unknown>;
    } catch {
      return stamped(
        400,
        JSON.stringify({
          as_of: asOf,
          error: `invalid JSON body: ${serdeJsonError(bodyText)}`,
        }),
        asOf,
      );
    }
    const str = (key: string): string =>
      typeof v[key] === "string" ? (v[key] as string) : "";
    const contactRaw = str("contact").trim();
    const report = {
      identifier: str("identifier"),
      category: categoryOf(str("category")),
      contact: contactRaw === "" ? null : contactRaw,
      details: str("details"),
    };
    const refused = admitFeedback(env, report.identifier);
    if (refused) return wireJson(429, { error: refused, refused: true });
    const rec: FeedbackRecord = {
      seq: feedbackRecords.length + 1,
      recorded_at: new Date().toISOString(),
      identifier: report.identifier,
      category: report.category,
      contact: report.contact,
      details: report.details,
    };
    // The store's admission validation (the native submit's refusals,
    // in the native order).
    if (rec.identifier.trim() === "") {
      return stamped(
        400,
        JSON.stringify({
          as_of: asOf,
          error: "`identifier` is required — a report is about something",
        }),
        asOf,
      );
    }
    if (rec.details.trim() === "") {
      return stamped(
        400,
        JSON.stringify({
          as_of: asOf,
          error: "`details` is required — a report states what did not match",
        }),
        asOf,
      );
    }
    if ([...rec.details].length > 500) {
      return stamped(
        400,
        JSON.stringify({ as_of: asOf, error: "`details` exceeds 500 characters" }),
        asOf,
      );
    }
    feedbackRecords.push(rec);
    // The receipt is the public form: contact withheld.
    return wireJson(201, feedbackJson(rec, false));
  }

  // GET /feedback/{seq} — the public citation form: the report by
  // sequence with the contact withheld (stated, never silent).
  const citation = pathname.match(/^\/feedback\/([^/]+)$/);
  if (citation) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed("GET,HEAD");
    }
    const raw = decodeURIComponent(citation[1]);
    if (!/^\d+$/.test(raw)) return pathRejection(raw);
    const seq = Number(raw);
    const rec = seq >= 1 ? feedbackRecords[seq - 1] : undefined;
    if (!rec) return noInformation(asOf);
    return wireJson(200, feedbackJson(rec, false), true);
  }

  // GET /admin/feedback?limit=&offset= — the full listing (contacts
  // included, newest first), admin-guarded when a token is configured.
  if (pathname === "/admin/feedback") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed("GET,HEAD");
    }
    const token = env.UNIDPP_GATEWAY_ADMIN_TOKEN;
    if (token) {
      const got = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/, "");
      if (got !== token) return wireJson(401, { error: "unauthorized" });
    }
    const nonNegative = (raw: string | null): number | null => {
      if (raw === null) return null;
      const n = Number(raw);
      return Number.isInteger(n) && n >= 0 ? n : null;
    };
    const limit = Math.min(nonNegative(params.get("limit")) ?? 100, 10_000);
    const offset = nonNegative(params.get("offset")) ?? 0;
    const slice = [...feedbackRecords]
      .reverse()
      .slice(offset, offset + limit)
      .map((rec) => feedbackJson(rec, true));
    return wireJson(200, { offset, records: slice, total: feedbackRecords.length }, true);
  }

  // POST /scan-tokens {source} — issue a scan token under the
  // configured policy (X-UniDPP-Source honored; absent policy the
  // gate is open and issuance is a stated no-op).
  if (pathname === "/scan-tokens") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    const bodyText = await request.text();
    let body: Record<string, unknown> = {};
    try {
      body = JSON.parse(bodyText) as Record<string, unknown>;
    } catch {
      // A body that is not JSON simply names no source (the native
      // parses opportunistically and falls through).
    }
    const source =
      request.headers.get("x-unidpp-source") ??
      (typeof body.source === "string" ? body.source : "anonymous");
    const issued = scanIssue(scanPolicyOf(env), source || "anonymous");
    if (issued.ok) {
      return wireJson(201, { source, token: issued.token, ttl_secs: issued.ttl });
    }
    if (issued.open) {
      return wireJson(409, { error: issued.reason, gate: "open" });
    }
    return scanRefusal(issued.reason, true);
  }

  return stamped(404, JSON.stringify({ error: "no such render route" }), asOf);
}

// ---------------------------------------------------------------------------
// The module root: the discovery document the native gateway serves
// at its bare prefix (GET /render under the estate prefix).
// ---------------------------------------------------------------------------

export async function discovery(
  request: Request,
  env: { tenant?: string },
): Promise<Response> {
  void request;
  void env.tenant;
  const asOf = isoStamp();
  // The fixtures index: the built-in demo passport (the native
  // fixture_index's shape; the gtin member rides only a GS1-keyed
  // subject).
  const fixtureText = fixturePassport();
  const fixtures: Record<string, unknown>[] = [];
  if (fixtureText) {
    const demo = JSON.parse(fixtureText) as {
      passport_id?: string;
      product_id?: string;
    };
    const entry: Record<string, unknown> = {
      passport_id: demo.passport_id ?? null,
      product_id: demo.product_id ?? null,
    };
    const subject = demo.product_id ?? "";
    if (subject.startsWith("01+")) entry.gtin = subject.split("+")[1] ?? "";
    fixtures.push(entry);
  }
  // The keys in the native document's (sorted) order; as_of first.
  const doc = {
    as_of: asOf,
    bindings: {
      en18222: {
        endpoint: "GET /en18222/v1/dppsByProductId/{gtin}",
        profile: "urn:unidpp:profile:render:en18222",
        rendering:
          "the EN 18222 REST shape: full (element tree, string-printed values) or compressed (collection-keyed, native JSON values); default compressed per the EN",
        semantics:
          "wire field set mirrored from the freeDPP live-endpoint artifacts (unidpp-py/conformance/competitors/freedpp/artifacts/*-api-{full,compressed}.json)",
      },
      untp: {
        endpoint: "GET /untp/product/{id}",
        identifier_mapping:
          "core cpid <-> https://unidpp.org/id/ (py iso-15459); gs1 family <-> https://gs1.org/voc/ with (01)/(10)/(21) application identifiers",
        profile: "urn:unidpp:profile:render:untp",
        rendering:
          "UNTP verifiable-credential triad: DigitalProductPassport VC (the py stub shape) + DigitalConformityCredentials (profile bindings + E14 inspection stamps) + link-resolver entry (log-head anchored)",
        semantics:
          "port of unidpp-py/unidpp/adapters/untp.py (parse_stub kept for round-trip) with the verify.py verdict rules over the evidence",
      },
    },
    build_id: "dev",
    c4: "both bindings are C4 protocol renderings of one neutral core — no region is the universal envelope; adding a protocol adds a render profile, never a fork",
    conventions: [
      "as-of stamped responses (x-as-of header; as_of body member except on the frozen EN 18222 wire)",
      "no-information 404s: identical bytes for unknown and deliberately unresolvable ids (I12)",
      "the gateway renders core passports in foreign shapes, and imports them back with a deterministic identity (render and ingest are inverse projections; imported documents carry an empty log — their events live in the source regime, the receipt records the origin)",
    ],
    description:
      "UniDPP interop gateway: renders the neutral core in foreign protocol shapes — their format is our profile. The py adapters are the semantics source; this service ports them and serves both renderings from one core.",
    endpoints: {
      en18222: "GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed",
      feedback:
        "POST /feedback {identifier, category: goods-mismatch|advertising-mismatch|other:<stated>, contact?, details<=500} — the consumer report channel: journaled, sequenced, receipted; admission control is deployment-pluggable (rate window via UNIDPP_GATEWAY_FEEDBACK_RATE; refusals state their reason)",
      feedback_admin:
        "GET /admin/feedback?limit=&offset= — the full listing, admin-guarded when UNIDPP_GATEWAY_ADMIN_TOKEN is set",
      feedback_citation:
        "GET /feedback/{seq} — the public citation form (contact withheld, stated)",
      health: "GET /healthz",
      scan_tokens:
        "POST /scan-tokens {source} — issue a scan token when a scan policy is configured (X-UniDPP-Source honored); TTL + issuance limit are deployment data (unidpp-config scan_policy); absent policy = the gate is open (public resolution is the default doctrine); refusals state themselves (401 absent/unknown/expired, 429 over limit)",
      untp: "GET /untp/product/{id}?freshness=",
      untp_ingest:
        "POST /untp/ingest (import direction: a UNTP passport VC or triad mints a core passport with a deterministic identity; idempotent per subject)",
    },
    service: "unidpp-gateway",
    source: {
      issuer_url: null,
      mode: "issuer-upstream-with-fixture-fallback",
      fixtures,
    },
    version: "0.1.0",
  };
  return stamped(200, JSON.stringify(doc), asOf);
}
