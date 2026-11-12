// The views surface on the estate (REARCH R12 S5-serve): the lens
// view computed through the wasm boundary — the same project() the
// native projector compiles. The passport rides the estate's own
// issuer DO; the lens item rides the estate's own registry DO (both
// in process); the fixtures fallback (the built-in EU/JP lens) rides
// the boundary's fixture module.

import { workerCore } from "./mount";

export interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const stamped = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    },
  });

function project(
  passportText: string,
  lensText: string,
  atSecs: number,
  actor: string,
): { ok: true; view: Record<string, unknown> } | { ok: false; error: string } {
  const core = workerCore();
  const encoder = new TextEncoder();
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = encoder.encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const passport = put(passportText);
  const lens = put(lensText);
  const actorPart = put(actor);
  const rc = core.unidpp_view_project(
    passport.ptr,
    passport.len,
    lens.ptr,
    lens.len,
    BigInt(Math.floor(atSecs)),
    actorPart.ptr,
    actorPart.len,
  );
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  [passport.ptr, lens.ptr, actorPart.ptr].forEach((ptr) => core.unidpp_free(ptr, 0));
  if (rc === 0) {
    return { ok: true, view: JSON.parse(note) as Record<string, unknown> };
  }
  return { ok: false, error: note || `the projection failed (${rc})` };
}

// The built-in fixture lens: the native fixtures module's own, via
// the wasm boundary — byte-exact with the native fallback.

export async function view(
  request: Request,
  env: {
    ISSUER?: DoNamespace;
    REGISTRY?: DoNamespace;
    tenant?: string;
  },
): Promise<Response> {
  // The tenant names the DO folder (R6): the id carries the suffix.
  const estate = (ns: DoNamespace, name: string) =>
    ns.get(ns.idFromName(env.tenant ? `${name}@${env.tenant}` : name));
  const params = new URL(request.url).searchParams;
  const passportId = params.get("passport")?.trim();
  const profile = params.get("profile")?.trim();
  const actor = params.get("actor")?.trim() || "anonymous";
  if (!passportId) return badRequest("`passport` query parameter is required");
  if (!profile) return badRequest("`profile` query parameter is required");
  const at = params.get("at") ?? params.get("asof");
  const atSecs = at ? Math.floor(Date.parse(at) / 1000) : Math.floor(Date.now() / 1000);

  // 1. The passport: the estate's own issuer DO; the built-in demo
  // passport is the stated fallback (the native fixtures doctrine).
  let passportText: string | null = null;
  let passportFromFixtures = false;
  if (env.ISSUER) {
    const stub = estate(env.ISSUER, "estate");
    const response = await stub.fetch(
      new Request(`https://do.internal/passports/${encodeURIComponent(passportId)}`),
    );
    if (response.status === 200) {
      const body = (await response.json()) as Record<string, unknown>;
      const document = { ...body };
      delete document.audit_seq;
      passportText = JSON.stringify(document);
    }
  }
  if (!passportText) {
    const core = workerCore();
    const rc = core.unidpp_fixture_passport();
    const notePtr = core.unidpp_alloc(1048576);
    const noteLen = core.unidpp_note_take(notePtr);
    const note = new TextDecoder().decode(
      new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
    );
    core.unidpp_free(notePtr, 1048576);
    if (rc !== 0) {
      return stamped(404, { error: `no passport \`${passportId}\`` });
    }
    const demo = JSON.parse(note) as { passport_id: string };
    if (passportId !== demo.passport_id) {
      return stamped(404, { error: `no passport \`${passportId}\`` });
    }
    passportText = note;
    passportFromFixtures = true;
  }

  // 2. The lens: the estate's own registry DO, else the built-in
  // fixture (the same fallback doctrine the native module carries).
  let lensText: string | null = null;
  let source = "registry";
  if (env.REGISTRY) {
    const stub = estate(env.REGISTRY, "estate");
    const response = await stub.fetch(
      new Request(`https://do.internal/profiles/${encodeURIComponent(profile)}`),
    );
    if (response.status === 200) {
      lensText = JSON.stringify(await response.json());
    }
  }
  if (!lensText) {
    const core = workerCore();
    const profileBytes = new TextEncoder().encode(profile);
    const profilePtr = core.unidpp_alloc(profileBytes.length);
    new Uint8Array(core.memory.buffer, profilePtr, profileBytes.length).set(profileBytes);
    const lensRc = core.unidpp_fixture_lens(profilePtr, profileBytes.length);
    core.unidpp_free(profilePtr, profileBytes.length);
    const notePtr = core.unidpp_alloc(1048576);
    const noteLen = core.unidpp_note_take(notePtr);
    const note = new TextDecoder().decode(
      new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
    );
    core.unidpp_free(notePtr, 1048576);
    if (lensRc !== 0) {
      return stamped(404, { error: `no profile item \`${profile}\` in the registry` });
    }
    lensText = note;
    source = "fixtures";
  }

  // 3. Project through the wasm boundary.
  const minted = project(passportText, lensText, atSecs, actor);
  if (!minted.ok) return stamped(502, { error: minted.error });
  const view = minted.view as Record<string, unknown>;
  if (view.passport && typeof view.passport === "object") {
    (view.passport as Record<string, unknown>).source = passportFromFixtures
      ? "fixtures"
      : source;
  }
  return stamped(200, view);
}
