// The render surface on the estate (REARCH R12 S5-serve): the EN 18222
// document and the UNTP verifiable-credential triad, computed through
// the wasm boundary — the same renderers the native gateway compiles.
// The passport rides the estate's own issuer DO; the built-in demo
// passport is the stated fallback (the native fixtures doctrine); the
// profile layer is the issuer's bound profiles (empty while none are
// bound). Unknown ids 404 no-information, identical bytes for unknown
// and deliberately unresolvable (I12).

import { workerCore } from "./mount";

export interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

const NOTE_CAPACITY = 1048576;

const stamped = (status: number, body: string, asOf: string): Response =>
  new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": asOf,
    },
  });

const noInformation = (asOf: string): Response => stamped(404, "{}", asOf);

// The verdict module's ISO 8601 duration rule (PnD(TnHnMn(.s)S)?),
// mirrored from verdict::duration_to_ms — null on a malformed body.
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

// The issuer's passport document (the audit sequence stripped), or
// null on a miss. The bound profile layer (clause 5) rides beside
// the document and returns separately for the render's profile
// refs.
async function issuerPassport(
  env: { ISSUER?: DoNamespace; tenant?: string },
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
  env: { ISSUER?: DoNamespace; tenant?: string },
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
  env: { ISSUER?: DoNamespace; tenant?: string },
): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const asOf = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const atSecs = Math.floor(Date.now() / 1000);

  // GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed
  const en = pathname.match(/^\/en18222\/v1\/dppsByProductId\/([^/]+)$/);
  if (en) {
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
    const id = decodeURIComponent(untp[1]);
    const freshness = (params.get("freshness") ?? "").trim();
    if (freshness && durationMs(freshness) === null) {
      return stamped(400, JSON.stringify({ error: "`freshness` must be an ISO 8601 duration (PnDTnHnMnS)" }), asOf);
    }
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

  return stamped(404, JSON.stringify({ error: "no such render route" }), asOf);
}
