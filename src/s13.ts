// The S13 seam on the edge (the adoption audit's cross-border gap):
// the wire the spec's [[cl-s13]] names and Annex B pins. The
// canonical encoders mirror the s13 crate's byte-for-byte framing
// (CN-1: every field u32-LE length-prefixed, little-endian
// everywhere), the signatures ride the wasm boundary's S13-MESSAGE
// domain (the signatif crate's own slot verify), and the golden
// fixtures gate every byte: the request digest, the response's
// canonical form, and the F2 signed-exchange vector's key ids.

import { CoreExports, digestHex } from "./wasm";
import { workerCore } from "./mount";

/** One length-prefixed field (u32 LE length, then the bytes) — the
 *  CanonicalWriter's framing. */
function lp(bytes: Uint8Array): Uint8Array {
  const head = new Uint8Array(4);
  new DataView(head.buffer).setUint32(0, bytes.length, true);
  const out = new Uint8Array(4 + bytes.length);
  out.set(head);
  out.set(bytes, 4);
  return out;
}

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export interface S13RequestDoc {
  verifier: string;
  subject: string;
  profile: string;
  segment: string;
  at: string;
}

/** The canonical, signable form: the five fields in declared order,
 *  each length-prefixed. */
export function canonicalRequestBytes(request: S13RequestDoc): Uint8Array {
  const parts = [request.verifier, request.subject, request.profile, request.segment, request.at].map(
    (field) => lp(utf8(field)),
  );
  return concat(parts);
}

export function requestDigest(core: CoreExports, request: S13RequestDoc): Uint8Array {
  return hexBytes(digestHex(core, canonicalRequestBytes(request)));
}

export interface S13OutcomeDoc {
  outcome: string;
  paired_with?: string;
  attestation_service?: string;
  escrow_quorum?: string;
  reason?: string;
}

export interface S13ResponseDoc {
  request_digest: number[];
  outcome: S13OutcomeDoc;
  governing_policy: string;
  governing_policy_version: number;
  custodian: string;
}

/** The outcome's stable wire token and its payload fields, in
 *  declaration order (the s13 crate's own `token`/`payload`). */
function outcomeParts(outcome: S13OutcomeDoc): { token: string; payload: Uint8Array[] } {
  switch (outcome.outcome) {
    case "permit":
      return { token: "permit", payload: [] };
    case "permit-paired":
      return { token: "permit-paired", payload: [utf8(outcome.paired_with ?? "")] };
    case "attestation-offer":
      return { token: "attestation-offer", payload: [utf8(outcome.attestation_service ?? "")] };
    case "escalation":
      return { token: "escalation", payload: [utf8(outcome.escrow_quorum ?? "")] };
    case "deny":
      return { token: "deny", payload: [utf8(outcome.reason ?? "")] };
    default:
      throw new Error(`unknown outcome \`${outcome.outcome}\``);
  }
}

/** The canonical form: request digest, outcome token, outcome
 *  payload fields, governing policy, version (u64 LE, itself
 *  length-prefixed), custodian — all length-prefixed. */
export function canonicalResponseBytes(response: S13ResponseDoc): Uint8Array {
  const { token, payload } = outcomeParts(response.outcome);
  const version = new Uint8Array(8);
  new DataView(version.buffer).setBigUint64(0, BigInt(response.governing_policy_version), true);
  return concat([
    lp(new Uint8Array(response.request_digest)),
    lp(utf8(token)),
    ...payload.map(lp),
    lp(utf8(response.governing_policy)),
    lp(version),
    lp(utf8(response.custodian)),
  ]);
}

/** The authority's counter-signature payload (XB-7): the answer's
 *  identity and place — digest, sequence, policy, version. */
export function authorityPayloadBytes(response: S13ResponseDoc, sequence: number): Uint8Array {
  const version = new Uint8Array(8);
  new DataView(version.buffer).setBigUint64(0, BigInt(response.governing_policy_version), true);
  const seq = new Uint8Array(8);
  new DataView(seq.buffer).setBigUint64(0, BigInt(sequence), true);
  return concat([
    lp(new Uint8Array(response.request_digest)),
    lp(seq),
    lp(utf8(response.governing_policy)),
    lp(version),
  ]);
}

/** The suite codes Annex B pins (the key id's digest input). */
const SUITE_CODES: Record<string, number> = { "ecdsa-p256": 1, ed25519: 6 };

/** `k-` + the first 16 hex chars of sha256(suite code || public). */
export function keyIdFor(core: CoreExports, suite: string, publicKey: Uint8Array): string {
  const code = SUITE_CODES[suite];
  if (code === undefined) throw new Error(`unknown suite \`${suite}\``);
  const input = new Uint8Array(1 + publicKey.length);
  input[0] = code;
  input.set(publicKey, 1);
  return `k-${digestHex(core, input).slice(0, 16)}`;
}

// --- the boundary calls -------------------------------------------------

function putBytes(core: CoreExports, bytes: Uint8Array): { ptr: number; len: number } {
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function takeNote(core: CoreExports): string {
  const capacity = core.unidpp_note_capacity();
  const outPtr = core.unidpp_alloc(capacity);
  const length = core.unidpp_note_take(outPtr);
  const text = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, outPtr, Math.max(length, 0)),
  );
  core.unidpp_free(outPtr, capacity);
  return text;
}

/** The s13 crate's own evaluate: the policy and the request ride as
 *  JSON, the response (digest binding, outcome, governing-policy
 *  citation) comes back through the note buffer. */
export function evaluate(
  core: CoreExports,
  policyJson: string,
  requestJson: string,
  custodian: string,
): { ok: true; response: S13ResponseDoc } | { ok: false; error: string } {
  const policy = putBytes(core, utf8(policyJson));
  const request = putBytes(core, utf8(requestJson));
  const cust = putBytes(core, utf8(custodian));
  const rc = core.unidpp_s13_evaluate(policy.ptr, policy.len, request.ptr, request.len, cust.ptr, cust.len);
  if (rc !== 0) return { ok: false, error: takeNote(core) || `the evaluation failed (${rc})` };
  try {
    return { ok: true, response: JSON.parse(takeNote(core)) as S13ResponseDoc };
  } catch {
    return { ok: false, error: "the evaluated response is not JSON" };
  }
}

/** Sign `payload` in the S13-MESSAGE domain with the key derived
 *  from the seed: the 64-byte ed25519 signature. */
export function signS13Message(core: CoreExports, seed: Uint8Array, payload: Uint8Array): Uint8Array {
  const seedPtr = putBytes(core, seed);
  const domain = putBytes(core, utf8("s13-message"));
  const body = putBytes(core, payload);
  const outPtr = core.unidpp_alloc(64);
  const rc = core.unidpp_sign_raw(seedPtr.ptr, domain.ptr, domain.len, body.ptr, body.len, outPtr);
  if (rc !== 0) throw new Error(`the s13 signature failed (${rc})`);
  return new Uint8Array(core.memory.buffer, outPtr, 64).slice();
}

/** Verify a domain-framed signature under one public key (the
 *  signatif crate's own slot verify on the boundary). */
export function verifyS13Message(
  core: CoreExports,
  suite: string,
  publicKey: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  const domain = putBytes(core, utf8("s13-message"));
  const suiteArg = putBytes(core, utf8(suite));
  const key = putBytes(core, publicKey);
  const body = putBytes(core, payload);
  const sig = putBytes(core, signature);
  const rc = core.unidpp_verify_raw(
    domain.ptr, domain.len,
    suiteArg.ptr, suiteArg.len,
    key.ptr, key.len,
    body.ptr, body.len,
    sig.ptr, sig.len,
  );
  return rc === 1;
}

/** The ed25519 public key for a seed (the operator derivation the
 *  tree head uses). */
export function seedPublicKey(core: CoreExports, seed: Uint8Array): Uint8Array {
  const seedPtr = putBytes(core, seed);
  const outPtr = core.unidpp_alloc(32);
  const rc = core.unidpp_head_public(seedPtr.ptr, outPtr);
  if (rc !== 0) throw new Error(`the key derivation failed (${rc})`);
  return new Uint8Array(core.memory.buffer, outPtr, 32).slice();
}

/** The signing seed: the deployment's hex seed (64 hex chars → 32
 *  bytes) or the deterministic dev seed — the degrade every estate
 *  operator carries. */
export function boundarySeed(core: CoreExports, envSeed: string | undefined, label: string): Uint8Array {
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return new Uint8Array((envSeed.trim().match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
  }
  return hexBytes(digestHex(core, utf8(label)));
}

// --- small helpers -------------------------------------------------------

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function hexBytes(hex: string): Uint8Array {
  return new Uint8Array((hex.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
}

export function bytesHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** The core, for callers that already hold one. */
export function core(): CoreExports {
  return workerCore();
}

// --- the dossier boundary (SI-9/10/11) ----------------------------------

export interface RouteStepDoc {
  step: string;
  subject?: string;
  mode?: string;
  counterpart?: string;
  kind?: string;
  digest?: number[];
  data_class?: string;
  service?: string;
  entry?: unknown;
  reason?: string;
}

export interface CanonicalDocument {
  canonical_hex: string;
  digest_hex: string;
}

export interface CompositionDoc {
  level: number;
  bottleneck: string | null;
  policy_bound: boolean;
}

function boundaryJson(core: CoreExports, rc: number): { ok: true; document: Record<string, unknown> } | { ok: false; error: string } {
  if (rc !== 0) return { ok: false, error: takeNote(core) || `the boundary call failed (${rc})` };
  try {
    return { ok: true, document: JSON.parse(takeNote(core)) as Record<string, unknown> };
  } catch {
    return { ok: false, error: "the boundary note is not JSON" };
  }
}

/** The verification route's canonical form through the crate's own
 *  encoder: the steps ride as JSON, the canonical bytes and the
 *  digest come back. */
export function routeCanonical(core: CoreExports, steps: RouteStepDoc[]): { ok: true; document: CanonicalDocument } | { ok: false; error: string } {
  const arg = putBytes(core, utf8(JSON.stringify(steps)));
  const outcome = boundaryJson(core, core.unidpp_s13_route_canonical(arg.ptr, arg.len));
  return outcome.ok ? { ok: true, document: (outcome.document as unknown as CanonicalDocument) } : outcome;
}

/** The coverage report's canonical form through the crate's own
 *  encoder. */
export function coverageCanonical(core: CoreExports, report: unknown): { ok: true; document: CanonicalDocument } | { ok: false; error: string } {
  const arg = putBytes(core, utf8(JSON.stringify(report)));
  const outcome = boundaryJson(core, core.unidpp_s13_coverage_canonical(arg.ptr, arg.len));
  return outcome.ok ? { ok: true, document: (outcome.document as unknown as CanonicalDocument) } : outcome;
}

/** The composition law (SI-10): the effective level is the minimum
 *  over the layer caps and the policy cap; the bottleneck is named. */
export function composeLaw(core: CoreExports, vector: unknown, policyCap: number): { ok: true; composition: CompositionDoc } | { ok: false; error: string } {
  const arg = putBytes(core, utf8(JSON.stringify(vector)));
  const outcome = boundaryJson(core, core.unidpp_s13_compose(arg.ptr, arg.len, BigInt(policyCap)));
  return outcome.ok ? { ok: true, composition: (outcome.document as unknown as CompositionDoc) } : outcome;
}
