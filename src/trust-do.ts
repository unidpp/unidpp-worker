// The trust surface on a Durable Object (REARCH R12 S3): the
// operator keyring derived deterministically from the seed through
// the wasm boundary, the receipt-verification path — a third party
// holding only the served anchors verifies a log receipt's signed
// tree head with no connection to the log — and, at contract parity
// with the native unidpp-trust one-binary, the trust-graph,
// trust-list, master-list, revocation, operator, evidence and audit
// surfaces. The routes mirror the native handlers' response shapes
// over the DO's own journaled state (which starts empty: reads answer
// the same documents with zero counts); unknown-id reads answer the
// native error texts verbatim.
//
// One degrade boundary is stated rather than faked: the responses
// here are not counter-signed — the estate's Durable Objects serve
// unsigned bodies, where the native service signs both suites in the
// tree-head domain. The live per-attestation and quorum verdicts
// verify through the wasm boundary's signing domains (the same
// explicit-degrade doctrine as the deferred signature suites: a
// verdict this service cannot compute is never invented).

import { journalFor, Journal } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";

interface Anchor {
  key_id: string;
  suite: string;
  public: string;
}

const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

function operatorSeed(core: CoreExports, envSeed: string | undefined): Uint8Array {
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return unhex(envSeed.trim());
  }
  // The deterministic dev seed: the digest of the fixed label, the
  // same degrade the native keyring carries.
  const label = "UNIDPP-LOG/OPERATOR-SEED";
  const bytes = new TextEncoder().encode(label);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, bytes.length, outPtr);
  const seed = out.slice();
  core.unidpp_free(ptr, bytes.length);
  core.unidpp_free(outPtr, 32);
  return seed;
}

function anchorOf(core: CoreExports, seed: Uint8Array): Anchor {
  const seedPtr = core.unidpp_alloc(32);
  new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
  const publicPtr = core.unidpp_alloc(32);
  const rc = core.unidpp_head_public(seedPtr, publicPtr);
  const publicKey = hex(new Uint8Array(core.memory.buffer, publicPtr, 32).slice());
  const idLen = core.unidpp_head_key_id(seedPtr, publicPtr);
  const keyId = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, publicPtr, idLen).slice(),
  );
  core.unidpp_free(seedPtr, 32);
  core.unidpp_free(publicPtr, 32);
  if (rc !== 0) throw new Error("the operator key derivation failed");
  return { key_id: keyId, suite: "ed25519", public: publicKey };
}

// ---------------------------------------------------------------------------
// Time (the native crate::time doctrine: strict RFC 3339 parsing,
// second resolution, canonical trailing-Z rendering)
// ---------------------------------------------------------------------------

const tsParse = (input: string): number | null => {
  const b = input;
  if (b.length < 10 || !/^\d{4}/.test(b) || b[4] !== "-") return null;
  const year = Number(b.slice(0, 4));
  if (!/^\d{2}$/.test(b.slice(5, 7)) || b[7] !== "-") return null;
  const month = Number(b.slice(5, 7));
  if (!/^\d{2}$/.test(b.slice(8, 10))) return null;
  const day = Number(b.slice(8, 10));
  if (month < 1 || month > 12) return null;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (day < 1 || day > monthDays) return null;
  let pos = 10;
  let hour = 0;
  let min = 0;
  let sec = 0;
  if (b.length > pos && (b[pos] === "T" || b[pos] === "t" || b[pos] === " ")) {
    if (b.length < pos + 9 || !/^\d{2}:\d{2}:\d{2}$/.test(b.slice(pos + 1, pos + 9))) {
      return null;
    }
    hour = Number(b.slice(pos + 1, pos + 3));
    min = Number(b.slice(pos + 4, pos + 6));
    sec = Number(b.slice(pos + 7, pos + 9));
    if (hour > 23 || min > 59 || sec > 59) return null;
    pos += 9;
    // Fractional seconds accepted and discarded (second resolution).
    if (b.length > pos && b[pos] === ".") {
      pos += 1;
      while (pos < b.length && b[pos] >= "0" && b[pos] <= "9") pos += 1;
    }
  }
  let offsetSecs = 0;
  if (pos < b.length) {
    if (b[pos] === "Z" || b[pos] === "z") {
      pos += 1;
    } else if (b[pos] === "+" || b[pos] === "-") {
      const sign = b[pos] === "-" ? -1 : 1;
      pos += 1;
      if (!/^\d{2}/.test(b.slice(pos, pos + 2))) return null;
      const oh = Number(b.slice(pos, pos + 2));
      pos += 2;
      if (b[pos] === ":") pos += 1;
      if (!/^\d{2}/.test(b.slice(pos, pos + 2))) return null;
      const om = Number(b.slice(pos, pos + 2));
      pos += 2;
      if (oh > 23 || om > 59) return null;
      offsetSecs = sign * (oh * 3600 + om * 60);
    } else {
      return null;
    }
    if (pos !== b.length) return null;
  }
  // Days from civil (Howard Hinnant's proleptic Gregorian), seconds.
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = month > 2 ? month - 3 : month + 9;
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  const days = era * 146097 + doe - 719468;
  return days * 86400 + hour * 3600 + min * 60 + sec - offsetSecs;
};

const tsFormat = (secs: number): string =>
  new Date(secs * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

const tsBad = (input: string): string =>
  `invalid timestamp \`${input}\` (expected RFC 3339 UTC)`;

const isoNow = (): string =>
  new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

const nowSecs = (): number => Math.floor(Date.now() / 1000);

// The `at` query parameter (alias `asof`): absent or empty means now.
const parseAt = (url: URL): { at: number | null } | { error: string } => {
  const raw = url.searchParams.get("at") ?? url.searchParams.get("asof");
  if (raw === null || raw === "") return { at: null };
  const secs = tsParse(raw);
  if (secs === null) return { error: `invalid \`at\` parameter: ${tsBad(raw)}` };
  return { at: secs };
};

const optQuery = (url: URL, key: string): string | null => {
  const raw = url.searchParams.get(key);
  const trimmed = raw?.trim();
  return trimmed ? trimmed : null;
};

// ---------------------------------------------------------------------------
// Wire helpers (the native crate::wire layer, TS port)
// ---------------------------------------------------------------------------

const SUITE_TOKENS = [
  "ed25519",
  "ecdsa-p256",
  "sm2",
  "ml-dsa-44",
  "ml-dsa-65",
  "ml-dsa-87",
  "slh-dsa-128s",
  "slh-dsa-192s",
] as const;

type SuiteToken = (typeof SUITE_TOKENS)[number];

const suiteSquash = (raw: string): string =>
  raw.trim().toLowerCase().replace(/-/g, "").replace(/_/g, "");

// The suite parse is case-insensitive over the dehyphenated token.
const suiteParse = (raw: string): SuiteToken | null => {
  const squashed = suiteSquash(raw);
  const found = SUITE_TOKENS.find((token) => token.replace(/-/g, "") === squashed);
  return found ?? null;
};

// The suite wire codes and framing budgets (the signatif tables).
const SUITE_CODES: Record<SuiteToken, number> = {
  "ecdsa-p256": 1,
  sm2: 2,
  "ml-dsa-44": 3,
  "ml-dsa-65": 4,
  "ml-dsa-87": 5,
  ed25519: 6,
  "slh-dsa-128s": 7,
  "slh-dsa-192s": 8,
};

const SUITE_SIGNATURE_LEN: Record<SuiteToken, number> = {
  "ecdsa-p256": 64,
  sm2: 64,
  "ml-dsa-44": 2420,
  "ml-dsa-65": 3309,
  "ml-dsa-87": 4627,
  ed25519: 64,
  "slh-dsa-128s": 7856,
  "slh-dsa-192s": 16224,
};

// The key id: `k-` + the first 16 hex chars of sha256(suite-code ||
// public bytes) — the signatif KeyId::of derivation.
const keyIdOf = (core: CoreExports, suite: SuiteToken, publicHex: string): string => {
  const bytes = unhex(publicHex);
  const data = new Uint8Array(bytes.length + 1);
  data[0] = SUITE_CODES[suite];
  data.set(bytes, 1);
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  const digest = hex(new Uint8Array(core.memory.buffer, outPtr, 32).slice());
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return `k-${digest.slice(0, 16)}`;
};

const nodeBad = (raw: string): string => `validation error: bad node id \`${raw}\``;

const isGraphicAscii = (raw: string): boolean => {
  for (let i = 0; i < raw.length; i += 1) {
    const code = raw.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
};

// NodeId::new: trim + lowercase + 1..128 ASCII graphic characters.
const nodeIdParse = (raw: string): string | null => {
  const n = raw.trim().toLowerCase();
  if (n.length === 0 || n.length > 128 || !isGraphicAscii(n)) return null;
  return n;
};

// KeyId::new: trim + 1..64 ASCII graphic characters.
const keyIdNew = (raw: string): string | null => {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 64 || !isGraphicAscii(trimmed)) return null;
  return trimmed;
};

// hex_decode: case-insensitive, 0x/0X prefixes stripped.
const hexDecode = (input: string): { bytes: Uint8Array } | { error: string } => {
  const trimmed = input.trim();
  const body =
    trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  if (body.length % 2 !== 0) {
    return { error: `hex string of odd length \`${body.length}\`` };
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < body.length; i += 2) {
    const hi = parseInt(body[i], 16);
    const lo = parseInt(body[i + 1], 16);
    if (Number.isNaN(hi)) return { error: `not a hex digit \`${body[i]}\`` };
    if (Number.isNaN(lo)) return { error: `not a hex digit \`${body[i + 1]}\`` };
    out[i / 2] = (hi << 4) | lo;
  }
  return { bytes: out };
};

// public_from_value: the raw-hex form, rebuilt through from_bytes —
// length and form identify the suite (32 = Ed25519, 65 = SEC1 P-256
// with the 0x04 prefix, 1952 = ML-DSA-65); the declared suite then
// must match the bytes.
const publicParse = (
  core: CoreExports,
  v: unknown,
):
  | { suite: SuiteToken; public: string; public_len: number; key_id: string }
  | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "public key must be an object" };
  }
  const suiteRaw = obj["suite"];
  if (typeof suiteRaw !== "string") return { error: "public key `suite` is required" };
  const hexRaw = obj["public"];
  if (typeof hexRaw !== "string") return { error: "public key `public` (hex) is required" };
  const decoded = hexDecode(hexRaw);
  if ("error" in decoded) return { error: decoded.error };
  const bytes = decoded.bytes;
  let parsed: SuiteToken;
  if (bytes.length === 32) {
    parsed = "ed25519";
  } else if (bytes.length === 65 && bytes[0] === 0x04) {
    parsed = "ecdsa-p256";
  } else if (bytes.length === 1952) {
    parsed = "ml-dsa-65";
  } else {
    return {
      error: `cryptographic error: not a SIGNATIF public key encoding (len ${bytes.length})`,
    };
  }
  if (suiteSquash(suiteRaw) !== suiteSquash(parsed)) {
    return {
      error: `public key suite mismatch: declared \`${suiteRaw}\`, bytes are \`${parsed}\``,
    };
  }
  const publicHex = hex(bytes);
  return {
    suite: parsed,
    public: publicHex,
    public_len: bytes.length,
    key_id: keyIdOf(core, parsed, publicHex),
  };
};

interface StoredSlot {
  suite: string;
  key_id: string;
  signature: string | null;
}

const slotParse = (v: unknown): { slot: StoredSlot } | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "signature slot must be an object" };
  }
  const suiteRaw = obj["suite"];
  if (typeof suiteRaw !== "string") return { error: "`suite` is required" };
  const suite = suiteParse(suiteRaw);
  if (!suite) return { error: `validation error: unknown suite \`${suiteRaw}\`` };
  const keyRaw = obj["key_id"];
  if (typeof keyRaw !== "string") return { error: "`key_id` is required" };
  const keyId = keyIdNew(keyRaw);
  if (!keyId) return { error: `validation error: bad key id \`${keyRaw}\`` };
  let signature: string | null = null;
  const sigRaw = obj["signature"];
  if (sigRaw !== undefined && sigRaw !== null) {
    if (typeof sigRaw !== "string") {
      return { error: "`signature` must be a hex string or null" };
    }
    const decoded = hexDecode(sigRaw);
    if ("error" in decoded) return { error: `\`signature\`: ${decoded.error}` };
    signature = hex(decoded.bytes);
    if (signature.length / 2 !== SUITE_SIGNATURE_LEN[suite]) {
      return {
        error: `signature length ${signature.length / 2} does not match the ${suite} framing budget ${SUITE_SIGNATURE_LEN[suite]}`,
      };
    }
  }
  return { slot: { suite, key_id: keyId, signature } };
};

// The signatif canonical-fields framing (Annex B): every field
// u32-LE length-prefixed, little-endian — the bytes the witness and
// quorum signatures cover.
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const u64le = (value: number | bigint): Uint8Array => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
};
const u32le = (value: number): Uint8Array => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
};
const canonicalFields = (fields: Uint8Array[]): Uint8Array => {
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

// The canonical bytes a master-list witness signature covers: (node,
// at.secs, at.nanos — the seconds i64-LE, the nanos u32-LE), per
// signatif's WitnessAttestation.
const witnessPayload = (node: string, secs: number, nanos: number): Uint8Array =>
  canonicalFields([utf8(node), u64le(secs), u32le(nanos)]);

// The canonical statement a revocation's quorum covers: (subject
// label, reason token, declared_by, window start, window end or
// i64::MAX), and the quorum payload wraps it with (quorum node,
// threshold).
interface StatementContext {
  label: string;
  reasonToken: string;
  declaredBy: string;
  windowStart: number;
  windowEnd: number | null;
}
const I64_MAX = 9223372036854775807n;
const revocationStatement = (ctx: StatementContext): Uint8Array =>
  canonicalFields([
    utf8(ctx.label),
    utf8(ctx.reasonToken),
    utf8(ctx.declaredBy),
    u64le(ctx.windowStart),
    u64le(ctx.windowEnd === null ? I64_MAX : ctx.windowEnd),
  ]);
const quorumPayload = (
  q: NonNullable<StoredRevocation["quorum"]>,
  ctx: StatementContext,
): Uint8Array => {
  const statement = revocationStatement(ctx);
  const head = canonicalFields([utf8(q.quorum)]);
  const out = new Uint8Array(head.length + 4 + statement.length);
  out.set(head);
  out.set(u32le(q.threshold), head.length);
  out.set(statement, head.length + 4);
  return out;
};

// The node kind rides the wire form (a token string or the
// threshold_group object); the members carry BTreeSet semantics
// (sorted, deduplicated).
const kindParse = (v: unknown): { kind: unknown } | { error: string } => {
  if (typeof v === "string") {
    if (v === "root" || v === "delegated" || v === "end") return { kind: v };
    return { error: `unknown node kind \`${v}\`` };
  }
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const group = (v as Record<string, unknown>)["threshold_group"];
    if (!group || typeof group !== "object" || Array.isArray(group)) {
      return { error: "`threshold_group` object is required" };
    }
    const g = group as Record<string, unknown>;
    if (typeof g["threshold"] !== "number") {
      return { error: "`threshold_group.threshold` is required" };
    }
    const membersRaw = g["members"];
    if (!Array.isArray(membersRaw)) {
      return { error: "`threshold_group.members` array is required" };
    }
    const members: string[] = [];
    for (const m of membersRaw) {
      if (typeof m !== "string") return { error: "members must be node-id strings" };
      const id = nodeIdParse(m);
      if (!id) return { error: nodeBad(m) };
      if (!members.includes(id)) members.push(id);
    }
    members.sort();
    return { kind: { threshold_group: { threshold: g["threshold"], members } } };
  }
  return { error: "node kind must be a string or object" };
};

// The operator view renders the kind in the Rust Debug form.
const kindDebug = (kind: unknown): string => {
  if (typeof kind === "string") {
    if (kind === "root") return "Root";
    if (kind === "delegated") return "Delegated";
    return "End";
  }
  const group = (kind as { threshold_group?: { threshold: number; members: string[] } })
    .threshold_group;
  if (!group) return "End";
  const members = group.members.map((m) => `NodeId("${m}")`).join(", ");
  return `ThresholdGroup { threshold: ${group.threshold}, members: {${members}} }`;
};

interface StoredNode {
  id: string;
  kind: unknown;
  keys: { key_id: string; suite: string; public: string; public_len: number }[];
}

const nodeWire = (node: StoredNode): Record<string, unknown> => ({
  id: node.id,
  kind: node.kind,
  keys: node.keys.map((k) => ({
    key_id: k.key_id,
    suite: k.suite,
    public: k.public,
    public_len: k.public_len,
  })),
});

interface StoredEdge {
  parent: string;
  child: string;
  scope: unknown;
  signatures: StoredSlot[];
}

// The scope rides verbatim; the Only layers carry BTreeSet order in
// the native rendering, so they are sorted when an edge is stored.
const normalizeScope = (scope: unknown): unknown => {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return scope;
  const out = { ...(scope as Record<string, unknown>) };
  for (const layer of ["authority", "product_group", "profile_version"]) {
    const value = out[layer];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const only = (value as Record<string, unknown>)["Only"];
      if (Array.isArray(only)) {
        out[layer] = { Only: [...only].sort() };
      }
    }
  }
  return out;
};

const edgeWire = (edge: StoredEdge): Record<string, unknown> => ({
  parent: edge.parent,
  child: edge.child,
  scope: edge.scope,
  signatures: edge.signatures.map((s) => ({
    suite: s.suite,
    key_id: s.key_id,
    signature: s.signature,
  })),
});

// An `Only` layer with an empty set admits nothing — the contradiction
// the graph refuses.
const scopeContradiction = (scope: unknown): boolean => {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return false;
  const obj = scope as Record<string, unknown>;
  for (const layer of ["authority", "product_group", "profile_version"]) {
    const value = obj[layer];
    if (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Array.isArray((value as Record<string, unknown>)["Only"]) &&
      ((value as Record<string, unknown>)["Only"] as unknown[]).length === 0
    ) {
      return true;
    }
  }
  return false;
};

// The trust-list entry record: not_before inserts, superseded_at
// withdraws (the entry's force read: at >= not_before and before the
// supersession).
interface StoredTrustEntry {
  node: string;
  not_before: number;
  superseded_at: number | null;
}

const entryInForce = (entry: StoredTrustEntry, at: number): boolean =>
  at >= entry.not_before && (entry.superseded_at === null || at < entry.superseded_at);

const entryText = (entry: StoredTrustEntry): Record<string, unknown> => ({
  node: entry.node,
  not_before: tsFormat(entry.not_before),
  superseded_at: entry.superseded_at === null ? null : tsFormat(entry.superseded_at),
});

const entryWire = (entry: StoredTrustEntry, forceAt: number | null): Record<string, unknown> => ({
  ...entryText(entry),
  ...(forceAt === null ? {} : { in_force_at_as_of: entryInForce(entry, forceAt) }),
});

interface StoredWitness {
  node: string;
  suite: string;
  key_id: string;
  public: string;
  public_len: number;
}

const witnessWire = (w: StoredWitness): Record<string, unknown> => ({
  node: w.node,
  suite: w.suite,
  key_id: w.key_id,
  public: w.public,
  public_len: w.public_len,
});

interface StoredAttestation {
  witness: string;
  at: string;
  slot: StoredSlot;
}

interface StoredMasterEntry {
  node: string;
  attestations: StoredAttestation[];
}

const masterEntryWire = (entry: StoredMasterEntry): Record<string, unknown> => ({
  node: entry.node,
  attestations: entry.attestations.map((a) => ({
    witness: a.witness,
    at: a.at,
    slot: a.slot,
  })),
});

interface StoredRevocation {
  subject: Record<string, unknown>;
  label: string;
  reason: Record<string, unknown>;
  retroactive: boolean;
  declared_at: number;
  declared_at_text: string;
  declared_by: string;
  window: { start: string; end: string | null; open: boolean };
  window_start: number;
  window_end: number | null;
  quorum: { quorum: string; threshold: number; signatures: StoredSlot[] } | null;
}

const revocationWire = (r: StoredRevocation): Record<string, unknown> => ({
  subject: r.subject,
  reason: r.reason,
  declared_at: r.declared_at_text,
  declared_by: r.declared_by,
  window: r.window,
  quorum: r.quorum
    ? {
        quorum: r.quorum.quorum,
        threshold: r.quorum.threshold,
        signatures: r.quorum.signatures.map((s) => ({
          suite: s.suite,
          key_id: s.key_id,
          signature: s.signature,
        })),
      }
    : null,
});

// Retroactive reasons void ab initio inside the distrust window;
// prospective reasons act forward from the effect moment.
const RETROACTIVE_TOKENS = ["misissuance", "fraudulent-issuance", "authority-compromised"];

const subjectParse = (v: unknown): { subject: Record<string, unknown>; label: string } | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "subject must be an object" };
  }
  const kind = obj["kind"];
  if (typeof kind !== "string") return { error: "`kind` is required" };
  const id = obj["id"];
  if (typeof id !== "string") return { error: "`id` is required" };
  switch (kind) {
    case "key": {
      const keyId = keyIdNew(id);
      if (!keyId) return { error: `validation error: bad key id \`${id}\`` };
      return {
        subject: { kind: "key", id: keyId, label: `key:${keyId}` },
        label: `key:${keyId}`,
      };
    }
    case "node": {
      const nodeId = nodeIdParse(id);
      if (!nodeId) return { error: nodeBad(id) };
      return {
        subject: { kind: "node", id: nodeId, label: `node:${nodeId}` },
        label: `node:${nodeId}`,
      };
    }
    case "passport":
      return {
        subject: { kind: "passport", id, label: `passport:${id}` },
        label: `passport:${id}`,
      };
    case "condition": {
      const nodeRaw = obj["node"];
      if (typeof nodeRaw !== "string") {
        return { error: "`node` is required for `condition`" };
      }
      const nodeId = nodeIdParse(nodeRaw);
      if (!nodeId) return { error: `\`node\`: ${nodeBad(nodeRaw)}` };
      const condition = obj["condition"];
      if (condition === undefined) {
        return { error: "`condition` (the scope-condition object) is required" };
      }
      const display = `${nodeId}:\`${JSON.stringify(sorted(condition))}\``;
      return {
        subject: {
          kind: "condition",
          id: display,
          label: `condition:${display}`,
          node: nodeId,
          condition,
        },
        label: `condition:${display}`,
      };
    }
    default:
      return {
        error: `unknown subject kind \`${kind}\` (expected key|node|passport|condition)`,
      };
  }
};

const reasonParse = (
  v: unknown,
): { reason: Record<string, unknown>; retroactive: boolean } | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "reason must be an object" };
  }
  const token = obj["token"];
  if (typeof token !== "string") return { error: "`token` is required" };
  const retroactive = RETROACTIVE_TOKENS.includes(token);
  const reqTs = (key: string): number | { error: string } => {
    const raw = obj[key];
    if (typeof raw !== "string") return { error: `\`${key}\` is required for \`${token}\`` };
    const secs = tsParse(raw);
    if (secs === null) return { error: `\`${key}\`: ${tsBad(raw)}` };
    return secs;
  };
  let param: Record<string, unknown> = {};
  switch (token) {
    case "key-compromise": {
      const after = reqTs("after");
      if (typeof after !== "number") return after;
      param = { after: tsFormat(after) };
      break;
    }
    case "cessation":
    case "affiliation-change":
    case "misissuance":
    case "fraudulent-issuance":
    case "condition-withdrawal":
      break;
    case "supersession": {
      const by = obj["by"];
      if (typeof by !== "string") return { error: "`by` is required for `supersession`" };
      const nodeId = nodeIdParse(by);
      if (!nodeId) return { error: `\`by\`: ${nodeBad(by)}` };
      param = { by: nodeId };
      break;
    }
    case "authority-compromised": {
      const detected = reqTs("detected_at");
      if (typeof detected !== "number") return detected;
      param = { detected_at: tsFormat(detected) };
      break;
    }
    default:
      return { error: `unknown reason token \`${token}\`` };
  }
  return { reason: { token, retroactive, ...param }, retroactive };
};

const windowParse = (
  v: unknown,
): { start: number; end: number | null } | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "interval must be an object" };
  }
  const startRaw = obj["start"];
  if (typeof startRaw !== "string") return { error: "`start` is required" };
  const start = tsParse(startRaw);
  if (start === null) return { error: tsBad(startRaw) };
  let end: number | null = null;
  const endRaw = obj["end"];
  if (endRaw !== undefined && endRaw !== null) {
    if (typeof endRaw !== "string") {
      return { error: "`end` must be an RFC 3339 string or null" };
    }
    if (endRaw !== "") {
      end = tsParse(endRaw);
      if (end === null) return { error: tsBad(endRaw) };
      if (end < start) {
        return { error: `window end ${tsFormat(end)} is before start ${tsFormat(start)}` };
      }
    }
  }
  return { start, end };
};

// The trust-list entry document: `node` and `not_before`; the
// optional `superseded_at` is the withdrawal.
const trustEntryParse = (v: unknown): { entry: StoredTrustEntry } | { error: string } => {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { error: "trust-list entry must be an object" };
  }
  const nodeRaw = obj["node"];
  if (typeof nodeRaw !== "string") return { error: "`node` is required" };
  const node = nodeIdParse(nodeRaw);
  if (!node) return { error: `\`node\`: ${nodeBad(nodeRaw)}` };
  const notBeforeRaw = obj["not_before"];
  if (typeof notBeforeRaw !== "string") {
    return { error: "`not_before` (RFC 3339) is required" };
  }
  const notBefore = tsParse(notBeforeRaw);
  if (notBefore === null) return { error: tsBad(notBeforeRaw) };
  let superseded: number | null = null;
  const supersededRaw = obj["superseded_at"];
  if (supersededRaw !== undefined && supersededRaw !== null) {
    if (typeof supersededRaw !== "string") {
      return { error: "`superseded_at` must be an RFC 3339 string or null" };
    }
    if (supersededRaw !== "") {
      superseded = tsParse(supersededRaw);
      if (superseded === null) return { error: tsBad(supersededRaw) };
    }
  }
  return { entry: { node, not_before: notBefore, superseded_at: superseded } };
};

// ---------------------------------------------------------------------------
// Canonical JSON: serde_json's default map is a BTreeMap, so the
// native documents render with recursively sorted object keys and a
// two-space indent. Responses mirror that rendering.
// ---------------------------------------------------------------------------

const sorted = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sorted(v)]),
    );
  }
  return value;
};

const CACHE_CURRENT = "public, max-age=30, must-revalidate";
const CACHE_POINT_IN_TIME = "public, max-age=86400, immutable";
const CACHE_NO_STORE = "no-store";

const jsonBody = (status: number, body: unknown, asOf: string, cache: string): Response =>
  new Response(JSON.stringify(sorted(body), null, 2), {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": asOf,
      "cache-control": cache,
    },
  });

const errorResponse = (status: number, message: string): Response =>
  jsonBody(status, { error: message }, isoNow(), CACHE_NO_STORE);

// The native router answers a wrong method on a routed path with an
// empty 405 (axum's fallback), mirrored here.
const methodNotAllowed = (): Response => new Response(null, { status: 405 });

// ---------------------------------------------------------------------------
// Store state (the native Store's in-memory half, journaled)
// ---------------------------------------------------------------------------

interface AuditRecord {
  seq: number;
  recorded_at: string;
  op: string;
  body: unknown;
  [key: string]: unknown;
}

interface StoredEvidence {
  id: string;
  content_type: string;
  description: string;
  required_scope: string;
  content: Uint8Array;
}

const evidenceMeta = (e: StoredEvidence): Record<string, unknown> => ({
  id: e.id,
  content_type: e.content_type,
  description: e.description,
  required_scope: e.required_scope,
  content_bytes: e.content.length,
});

export class TrustDO {
  private journal: Journal;
  private core: CoreExports;
  private anchor: Anchor | null = null;
  private loaded = false;

  // The store: graph, trust lists (keyed by normalized jurisdiction),
  // master list, revocation ledger, evidence, audit log.
  private nodes = new Map<string, StoredNode>();
  private edges: StoredEdge[] = [];
  private trustLists = new Map<
    string,
    { jurisdiction: string; entries: Map<string, StoredTrustEntry> }
  >();
  private frameworks = new Map<string, string | null>();
  private masterM = 1;
  private witnesses = new Map<string, StoredWitness>();
  private masterEntries = new Map<string, StoredMasterEntry>();
  private revocations: StoredRevocation[] = [];
  private evidence = new Map<string, StoredEvidence>();
  private log: AuditRecord[] = [];

  constructor(
    stateOrStorage: unknown,
    private readonly env: Record<string, string | undefined>,
  ) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
  }

  private anchorOf(): Anchor {
    if (!this.anchor) {
      this.anchor = anchorOf(this.core, operatorSeed(this.core, this.env.UNIDPP_LOG_SEED));
    }
    return this.anchor;
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      // Replay: every journal entry is an audit record whose shape is
      // the public wire shape — the state rebuilds through apply and
      // the audit log rebuilds from the same records, in seq order.
      for (const rec of await this.journal.all()) {
        this.apply(rec);
        if (typeof rec.op === "string" && typeof rec.seq === "number") {
          this.log.push({
            seq: rec.seq,
            recorded_at: String(rec.recorded_at ?? ""),
            op: rec.op,
            body: rec.body,
          });
        }
      }
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (path === "/healthz") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "content-type": "application/json" },
      });
    }
    // Every routed path answers 405 on a method it does not carry
    // (the native router's contract probe posture).
    if (path === "/keyring") {
      if (method === "GET") return this.keyring();
      return methodNotAllowed();
    }
    if (path === "/verify") {
      if (method === "POST") return this.verify(request);
      return methodNotAllowed();
    }
    if (path === "/") {
      if (method === "GET") return this.discovery();
      return methodNotAllowed();
    }
    if (path === "/graph") {
      if (method === "GET") return this.graphRead(url);
      return methodNotAllowed();
    }
    if (path === "/anchor-bundle") {
      if (method === "GET") return this.anchorBundle(url);
      return methodNotAllowed();
    }
    if (path === "/trust-lists") {
      if (method === "GET") return this.trustListsRead(url);
      if (method === "POST") return this.registerTrustList(request);
      return methodNotAllowed();
    }
    const listEntries = path.match(/^\/trust-lists\/([^/]+)\/entries$/);
    if (listEntries) {
      if (method === "POST") return this.upsertTrustEntry(listEntries[1], request);
      return methodNotAllowed();
    }
    const listOne = path.match(/^\/trust-lists\/([^/]+)$/);
    if (listOne) {
      if (method === "GET") return this.trustListOne(listOne[1], url);
      return methodNotAllowed();
    }
    if (path === "/master-list") {
      if (method === "GET") return this.masterList(url);
      return methodNotAllowed();
    }
    if (path === "/master-list/witnesses") {
      if (method === "POST") return this.setWitnesses(request);
      return methodNotAllowed();
    }
    if (path === "/master-list/entries") {
      if (method === "POST") return this.upsertMasterEntry(request);
      return methodNotAllowed();
    }
    if (path === "/revocations") {
      if (method === "GET") return this.revocationsRead(url);
      if (method === "POST") return this.declareRevocation(request);
      return methodNotAllowed();
    }
    const operator = path.match(/^\/operators\/([^/]+)$/);
    if (operator) {
      if (method === "GET") return this.operatorView(operator[1], url);
      return methodNotAllowed();
    }
    if (path === "/evidence") {
      if (method === "GET") return this.evidenceCatalogue();
      return methodNotAllowed();
    }
    const evidenceOne = path.match(/^\/evidence\/([^/]+)$/);
    if (evidenceOne) {
      if (method === "GET") return this.evidenceRelease(evidenceOne[1], url, request);
      return methodNotAllowed();
    }
    if (path === "/admin/log") {
      if (method === "GET") {
        const deny = this.guardFor(request);
        if (deny) return deny;
        return this.adminLog(url);
      }
      return methodNotAllowed();
    }
    if (path === "/admin/evidence") {
      if (method === "POST") {
        const deny = this.guardFor(request);
        if (deny) return deny;
        return this.registerEvidence(request);
      }
      return methodNotAllowed();
    }
    if (path === "/nodes") {
      if (method === "POST") {
        const deny = this.guardFor(request);
        if (deny) return deny;
        return this.registerNode(request);
      }
      return methodNotAllowed();
    }
    if (path === "/edges") {
      if (method === "POST") {
        const deny = this.guardFor(request);
        if (deny) return deny;
        return this.addEdge(request);
      }
      return methodNotAllowed();
    }
    return new Response(JSON.stringify({ error: "no such path" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }

  // The admin gate: the deployment's bearer token guards the operator
  // surface (mutations and /admin/log) exactly where the native
  // module gates on UNIDPP_TRUST_ADMIN_TOKEN; an unconfigured
  // deployment serves open, as the native dev mode does.
  private guardFor(request: Request): Response | null {
    const token = this.env.UNIDPP_TRUST_ADMIN_TOKEN;
    if (!token) return null;
    const presented = request.headers.get("authorization");
    if (presented !== `Bearer ${token}`) {
      return errorResponse(401, "unauthorized");
    }
    return null;
  }

  private keyring(): Response {
    const anchor = this.anchorOf();
    return new Response(
      JSON.stringify({
        keyring: "unidpp-trust",
        anchors: [anchor],
        as_of: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      }),
      { headers: { "content-type": "application/json", "x-as-of": new Date().toISOString() } },
    );
  }

  // -- journal replay ---------------------------------------------------
  //
  // The journal is the store: every mutation appends one record whose
  // shape is the public wire shape (round-trippable), and replay
  // rebuilds the state from the records in order.

  private apply(op: { op?: unknown; [key: string]: unknown }): void {
    const name = typeof op.op === "string" ? op.op : "";
    switch (name) {
      case "register-node": {
        const node = op.body as StoredNode;
        const existing = this.nodes.get(node.id);
        if (!existing) {
          this.nodes.set(node.id, { id: node.id, kind: node.kind, keys: [...node.keys] });
        } else {
          // Merge semantics: the incoming kind is the current
          // assertion; keys merge by key id into the same node.
          existing.kind = node.kind;
          for (const k of node.keys) {
            if (!existing.keys.some((ek) => ek.key_id === k.key_id)) {
              existing.keys.push(k);
            }
          }
        }
        return;
      }
      case "add-edge":
        this.edges.push(op.body as StoredEdge);
        return;
      case "register-trust-list": {
        const body = op.body as { jurisdiction: string; framework: string | null };
        const key = body.jurisdiction.toUpperCase();
        if (this.trustLists.has(key)) return;
        this.trustLists.set(key, { jurisdiction: body.jurisdiction, entries: new Map() });
        this.frameworks.set(key, body.framework);
        return;
      }
      case "upsert-trust-entry": {
        const body = op.body as {
          jurisdiction: string;
          node: string;
          not_before: string;
          superseded_at: string | null;
        };
        const list = this.trustLists.get(body.jurisdiction.toUpperCase());
        if (!list) return;
        const notBefore = tsParse(body.not_before);
        if (notBefore === null) return;
        this.applyEntry(list, {
          node: body.node,
          not_before: notBefore,
          superseded_at: body.superseded_at === null ? null : tsParse(body.superseded_at),
        });
        return;
      }
      case "set-witnesses": {
        const body = op.body as { m: number; witnesses: StoredWitness[] };
        if (body.m === 0 || body.witnesses.length === 0 || body.m > body.witnesses.length) {
          return;
        }
        // Entries survive a witness-set change: the attestations carry
        // their witness, so they re-verify (or stop verifying) against
        // the new set.
        this.masterM = body.m;
        this.witnesses = new Map(body.witnesses.map((w) => [w.node, w]));
        return;
      }
      case "upsert-master-entry": {
        const entry = op.body as StoredMasterEntry;
        if (entry.attestations.some((a) => !this.witnesses.has(a.witness))) return;
        this.masterEntries.set(entry.node, entry);
        return;
      }
      case "declare-revocation":
        this.revocations.push(op.body as StoredRevocation);
        return;
      case "register-evidence": {
        const body = op.body as {
          id: string;
          content_type: string;
          description: string;
          required_scope: string;
          content_hex: string;
        };
        if (this.evidence.has(body.id)) return;
        this.evidence.set(body.id, {
          id: body.id,
          content_type: body.content_type,
          description: body.description,
          required_scope: body.required_scope,
          content: unhex(body.content_hex),
        });
        return;
      }
      case "evidence-released":
        return;
      default:
        return;
    }
  }

  private async record(op: string, body: unknown): Promise<AuditRecord> {
    const rec: AuditRecord = {
      seq: this.log.length + 1,
      recorded_at: isoNow(),
      op,
      body,
    };
    await this.journal.append(rec);
    this.log.push(rec);
    return rec;
  }

  private applyEntry(
    list: { jurisdiction: string; entries: Map<string, StoredTrustEntry> },
    entry: StoredTrustEntry,
  ): void {
    const existing = list.entries.get(entry.node);
    if (existing) {
      if (existing.not_before !== entry.not_before) existing.not_before = entry.not_before;
      existing.superseded_at = entry.superseded_at;
    } else {
      list.entries.set(entry.node, entry);
    }
  }

  private sortedNodes(): StoredNode[] {
    return [...this.nodes.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  }

  private sortedEntries(): StoredMasterEntry[] {
    return [...this.masterEntries.values()].sort((a, b) => (a.node < b.node ? -1 : 1));
  }

  private sortedWitnesses(): StoredWitness[] {
    return [...this.witnesses.values()].sort((a, b) => (a.node < b.node ? -1 : 1));
  }

  private sortedListEntries(list: {
    entries: Map<string, StoredTrustEntry>;
  }): StoredTrustEntry[] {
    return [...list.entries.values()].sort((a, b) => (a.node < b.node ? -1 : 1));
  }

  private asOfOf(at: number | null): string {
    return at === null ? isoNow() : tsFormat(at);
  }

  private cacheOf(at: number | null): string {
    return at === null ? CACHE_CURRENT : CACHE_POINT_IN_TIME;
  }

  // -- reads ------------------------------------------------------------

  private discovery(): Response {
    return jsonBody(
      200,
      {
        service: "unidpp-trust",
        version: "0.1.0",
        build_id: "dev",
        description:
          "UniDPP trust-list service: jurisdiction trust lists per framework, M-of-K multi-witness master list, live reason-to-retroactivity revocations. All responses signed in the tree-head domain.",
        signing: {
          domain: "tree-head",
          adapter_note:
            "SIGNATIF has no service-response domain; tree-head (operator's signed statement of state, used for transparency-log signed tree heads) is the closest documented adaptation. Signatures cover the exact body bytes.",
          suites: ["ed25519", "ecdsa-p256"],
          headers: {
            as_of: "x-as-of",
            domain: "x-sig-domain",
            ed25519_signature: "x-sig-ed25519",
            ed25519_key_id: "x-sig-key-id-ed25519",
            ecdsa_p256_signature: "x-sig-ecdsa-p256",
            ecdsa_p256_key_id: "x-sig-key-id-ecdsa-p256",
            etag: "etag",
            cache_control: "cache-control",
          },
          keyring_endpoint: "/keyring",
        },
        endpoints: {
          discovery: "GET /",
          health: "GET /healthz",
          keyring: "GET /keyring",
          trust_lists: "GET /trust-lists?at=&jurisdiction=&framework=",
          trust_list_one: "GET /trust-lists/{jur}?at=",
          master_list: "GET /master-list",
          revocations: "GET /revocations?at=&known_by=&window=&subject=&retroactive=",
          operators:
            "GET /operators/{node}?at= — the operator surface: identity (kind, keys), delegation position (edges with scopes), trust-list memberships with validity windows (not_before/superseded_at), master-list attestations, revocation standing",
          evidence_catalogue:
            "GET /evidence — metadata only (ids, content types, required scopes, sizes); content never listed",
          evidence_release:
            "GET /evidence/{id}?scope= (or X-UniDPP-Scope; requester via ?requester= / X-UniDPP-Requester) — released bytes signed over; an unsatisfying scope is a stated 403 naming the required scope; every release journaled",
          graph: "GET /graph",
          anchor_bundle: "GET /anchor-bundle?jurisdiction=",
          admin_log: "GET /admin/log?limit=&offset=",
          register_node: "POST /nodes",
          add_edge: "POST /edges",
          register_trust_list: "POST /trust-lists",
          upsert_trust_entry: "POST /trust-lists/{jur}/entries",
          set_witnesses: "POST /master-list/witnesses",
          upsert_master_entry: "POST /master-list/entries",
          declare_revocation: "POST /revocations",
        },
        revocation_semantics: {
          prospective_reasons: [
            "key-compromise",
            "cessation",
            "supersession",
            "affiliation-change",
          ],
          retroactive_reasons: [
            "misissuance",
            "fraudulent-issuance",
            "authority-compromised",
          ],
          rule:
            "Prospective reasons keep prior as-of verifications valid (timestamping protects, like code signing). Retroactive reasons (misissuance, fraud, authority-compromised) void ab initio within the explicit distrust window [start, end] and re-validate outside it. Both readings are visible per-declaration in the response via `known_at_cutoff` and `voids_at_as_of`.",
        },
        as_of: {
          query_parameter: "at (alias: asof)",
          response_header: "x-as-of",
          point_in_time_cache:
            "responses to ?at=... carry cache-control: public, max-age=86400, immutable",
        },
        seed_fixtures: {
          source:
            "unidpp-signatif tests/common topology + scenario_misissuance (T0-anchored; see README)",
          enabled_by_default: false,
          note: "the edge seeds no fixture topology; the native trust service seeds it on first start (its default, disabled there with UNIDPP_TRUST_NO_SEED_FIXTURES=1)",
        },
        auth: "mutations and /admin/log require a Bearer token when UNIDPP_TRUST_ADMIN_TOKEN is set",
      },
      isoNow(),
      CACHE_CURRENT,
    );
  }

  private graphRead(url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        as_of: asOf,
        node_count: this.nodes.size,
        edge_count: this.edges.length,
        nodes: this.sortedNodes().map(nodeWire),
        edges: this.edges.map(edgeWire),
      },
      asOf,
      this.cacheOf(at.at),
    );
  }

  private anchorBundle(url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const jur = optQuery(url, "jurisdiction");
    if (!jur) return errorResponse(400, "`jurisdiction` query parameter is required");
    const list = this.trustLists.get(jur.toUpperCase());
    if (!list) return errorResponse(404, `no trust list \`${jur}\``);
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        as_of: asOf,
        jurisdiction: jur,
        trust_lists: [
          {
            jurisdiction: list.jurisdiction,
            entries: this.sortedListEntries(list).map((e) => entryWire(e, null)),
          },
        ],
        master: {
          m: this.masterM,
          k: this.witnesses.size,
          witnesses: this.sortedWitnesses().map((w) => ({
            node: w.node,
            suite: w.suite,
            public: w.public,
            public_len: w.public_len,
          })),
          entries: this.sortedEntries().map(masterEntryWire),
        },
      },
      asOf,
      this.cacheOf(at.at),
    );
  }

  private trustListsRead(url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const frameworkFilter = optQuery(url, "framework");
    const jurFilter = optQuery(url, "jurisdiction")?.toUpperCase() ?? null;
    const out: Record<string, unknown>[] = [];
    for (const [key, list] of this.trustLists) {
      if (jurFilter && key !== jurFilter) continue;
      const framework = this.frameworks.get(key) ?? null;
      if (frameworkFilter && framework !== frameworkFilter) continue;
      out.push({
        jurisdiction: list.jurisdiction,
        framework,
        entries: this.sortedListEntries(list).map((e) => entryWire(e, at.at ?? nowSecs())),
      });
    }
    out.sort((a, b) => (String(a.jurisdiction) < String(b.jurisdiction) ? -1 : 1));
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      { as_of: asOf, count: out.length, trust_lists: out },
      asOf,
      this.cacheOf(at.at),
    );
  }

  private trustListOne(jur: string, url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const key = jur.toUpperCase();
    const list = this.trustLists.get(key);
    if (!list) return errorResponse(404, `no trust list \`${jur}\``);
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        as_of: asOf,
        jurisdiction: list.jurisdiction,
        framework: this.frameworks.get(key) ?? null,
        entries: this.sortedListEntries(list).map((e) => entryWire(e, at.at ?? nowSecs())),
      },
      asOf,
      this.cacheOf(at.at),
    );
  }

  private masterList(url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    // The live per-attestation verification runs in the
    // MasterListWitness signing domain over the attestation's
    // canonical bytes against the registered witness key — the same
    // verification the native store renders.
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        as_of: asOf,
        m_of_k: { m: this.masterM, k: this.witnesses.size },
        witnesses: this.sortedWitnesses().map(witnessWire),
        entries: this.sortedEntries().map((entry) => {
          const verified = entry.attestations.map((a) =>
            this.attestationVerified(entry.node, a),
          );
          const distinct = new Set<string>();
          entry.attestations.forEach((a, i) => {
            if (verified[i]) distinct.add(a.witness);
          });
          return {
            node: entry.node,
            attestations: entry.attestations.map((a, i) => ({
              witness: a.witness,
              at: a.at,
              slot: a.slot,
              verified: verified[i],
            })),
            verified_witnesses: distinct.size,
            quorate: distinct.size >= this.masterM,
            threshold_required: this.masterM,
          };
        }),
      },
      asOf,
      this.cacheOf(at.at),
    );
  }

  // Live verification through the boundary: the signature slot
  // verifies in the named signing domain over the payload bytes
  // against the registered public key.
  private verifySlot(
    domain: string,
    suite: string,
    publicHex: string,
    payload: Uint8Array,
    slot: StoredSlot,
  ): boolean {
    if (!slot.signature) return false;
    const core = this.core;
    const put = (bytes: Uint8Array): { ptr: number; len: number } => {
      const ptr = core.unidpp_alloc(bytes.length);
      new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
      return { ptr, len: bytes.length };
    };
    const domainB = put(utf8(domain));
    const suiteB = put(utf8(suite));
    const publicB = put(unhex(publicHex));
    const payloadB = put(payload);
    const sigB = put(unhex(slot.signature));
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
    return rc === 1;
  }

  private attestationVerified(node: string, att: StoredAttestation): boolean {
    const witness = this.witnesses.get(att.witness);
    if (!witness) return false;
    const ms = Date.parse(att.at);
    if (Number.isNaN(ms)) return false;
    const payload = witnessPayload(
      node,
      Math.floor(ms / 1000),
      (ms % 1000) * 1_000_000,
    );
    return this.verifySlot(
      "master-list-witness",
      witness.suite,
      witness.public,
      payload,
      att.slot,
    );
  }

  // The two-form quorum verdict: a slot verifying under the quorum
  // node's own registered key certifies the group form; otherwise the
  // distinct verifying member keys resolvable through the directory
  // count toward the threshold.
  private quorumVerdictOf(
    q: NonNullable<StoredRevocation["quorum"]>,
    ctx: StatementContext,
  ): Record<string, unknown> {
    const quorumNode = this.nodes.get(q.quorum);
    const quorumKeyIds = new Set((quorumNode?.keys ?? []).map((k) => k.key_id));
    const byKeyId = new Map<string, { suite: string; public: string }>();
    for (const node of this.nodes.values()) {
      for (const k of node.keys) byKeyId.set(k.key_id, { suite: k.suite, public: k.public });
    }
    for (const w of this.witnesses.values()) {
      byKeyId.set(w.key_id, { suite: w.suite, public: w.public });
    }
    const payload = quorumPayload(q, ctx);
    let groupVerified = false;
    if (quorumNode) {
      for (const slot of q.signatures) {
        const key = quorumNode.keys.find((k) => k.key_id === slot.key_id);
        if (key && this.verifySlot("quorum", key.suite, key.public, payload, slot)) {
          groupVerified = true;
          break;
        }
      }
    }
    const members = new Set<string>();
    for (const slot of q.signatures) {
      if (quorumKeyIds.has(slot.key_id)) continue;
      const key = byKeyId.get(slot.key_id);
      if (key && this.verifySlot("quorum", key.suite, key.public, payload, slot)) {
        members.add(slot.key_id);
      }
    }
    const group = quorumNode?.kind as
      | { threshold_group?: { threshold?: number } }
      | string
      | undefined;
    const nodeThreshold =
      group && typeof group === "object"
        ? (group.threshold_group?.threshold ?? null)
        : null;
    const groupCertifies = groupVerified && nodeThreshold === q.threshold;
    return {
      form: groupCertifies ? "threshold-group" : "member-keys",
      verified_count: members.size,
      group_verified: groupVerified,
      quorate: groupCertifies || members.size >= q.threshold,
    };
  }

  private revocationsRead(url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const asOfInstant = at.at ?? nowSecs();
    const knownByRaw = optQuery(url, "known_by");
    let knownBy: number | null = null;
    if (knownByRaw) {
      knownBy = tsParse(knownByRaw);
      if (knownBy === null) return errorResponse(400, `\`known_by\`: ${tsBad(knownByRaw)}`);
    }
    const subjectFilter = optQuery(url, "subject");
    const retroRaw = optQuery(url, "retroactive");
    let retroFilter: boolean | null = null;
    if (retroRaw) {
      const lowered = retroRaw.toLowerCase();
      if (lowered === "true" || lowered === "1" || lowered === "yes") retroFilter = true;
      else if (lowered === "false" || lowered === "0" || lowered === "no") retroFilter = false;
      else return errorResponse(400, `\`retroactive\` must be true/false: \`${retroRaw}\``);
    }
    let windowFilter: { start: number; end: number | null } | null = null;
    const windowRaw = optQuery(url, "window");
    if (windowRaw) {
      const pair = windowRaw.includes("..")
        ? windowRaw.split("..")
        : windowRaw.includes(",")
          ? windowRaw.split(",")
          : null;
      if (!pair) {
        return errorResponse(
          400,
          `\`window\` must be \`START..END\` or \`START,END\`: \`${windowRaw}\``,
        );
      }
      const startText = pair[0].trim();
      const start = tsParse(startText);
      if (start === null) return errorResponse(400, `window start: ${tsBad(startText)}`);
      let end: number | null = null;
      if (pair[1] && pair[1].trim() !== "") {
        const endText = pair[1].trim();
        end = tsParse(endText);
        if (end === null) return errorResponse(400, `window end: ${tsBad(endText)}`);
      }
      windowFilter = { start, end };
    }
    const out: Record<string, unknown>[] = [];
    let seq = 0;
    for (const r of this.revocations) {
      seq += 1;
      if (retroFilter !== null && r.retroactive !== retroFilter) continue;
      if (subjectFilter && r.label !== subjectFilter && !r.label.startsWith(subjectFilter)) {
        continue;
      }
      if (windowFilter) {
        const windowEnd = r.window_end ?? r.window_start;
        const containsStart =
          windowFilter.start >= r.window_start && windowFilter.start <= windowEnd;
        const containsEnd =
          windowFilter.end !== null
            ? windowFilter.end >= r.window_start && windowFilter.end <= windowEnd
            : r.window_end === null;
        if (!(containsStart || containsEnd)) continue;
      }
      const knownAtCutoff = knownBy === null || r.declared_at <= knownBy;
      const voidsAtAsOf =
        knownAtCutoff &&
        asOfInstant >= r.window_start &&
        (r.window_end === null || asOfInstant <= r.window_end);
      out.push({
        seq,
        subject: r.subject,
        reason: r.reason,
        declared_at: r.declared_at_text,
        declared_by: r.declared_by,
        window: r.window,
        quorum: r.quorum
          ? {
              // The live quorum verdict: the Quorum signing domain
              // over the attestation's canonical payload, the group
              // form (a slot under the quorum node's own registered
              // key) or the member form (distinct verifying keys
              // resolvable through the directory) — the same
              // two-form verdict the native renders.
              quorum: r.quorum.quorum,
              threshold: r.quorum.threshold,
              ...this.quorumVerdictOf(r.quorum, {
                label: r.label,
                reasonToken: String((r.reason as { token: string }).token),
                declaredBy: r.declared_by,
                windowStart: r.window_start,
                windowEnd: r.window_end,
              }),
              signatures: r.quorum.signatures,
            }
          : null,
        known_at_cutoff: knownAtCutoff,
        voids_at_as_of: voidsAtAsOf,
        standing_at_as_of: !voidsAtAsOf
          ? "valid"
          : r.retroactive
            ? "void-ab-initio"
            : "suspended-from",
        verifications_at_stand: !voidsAtAsOf,
        rule: r.retroactive
          ? "retroactive: artifacts dated inside the window are void ab initio; outside re-validated"
          : "prospective: acts dated before the window/open-end stand; from the effect moment onward, suspended",
      });
    }
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        as_of: asOf,
        known_by: knownBy === null ? null : tsFormat(knownBy),
        query: {
          at: at.at === null ? null : tsFormat(at.at),
          known_by: knownBy === null ? null : tsFormat(knownBy),
          subject: subjectFilter,
          retroactive: retroFilter,
          window: windowFilter
            ? {
                start: tsFormat(windowFilter.start),
                end: windowFilter.end === null ? null : tsFormat(windowFilter.end),
              }
            : null,
        },
        semantics: {
          prospective_reasons: [
            "key-compromise",
            "cessation",
            "supersession",
            "affiliation-change",
          ],
          retroactive_reasons: [
            "misissuance",
            "fraudulent-issuance",
            "authority-compromised",
          ],
          rule:
            "Prospective reasons keep prior as-of verifications valid. Retroactive reasons (misissuance/fraud) void ab initio within the explicit window and re-validate outside it.",
        },
        count: out.length,
        revocations: out,
      },
      asOf,
      this.cacheOf(at.at),
    );
  }

  private operatorView(nodeRaw: string, url: URL): Response {
    const at = parseAt(url);
    if ("error" in at) return errorResponse(400, at.error);
    const nodeId = nodeIdParse(nodeRaw);
    if (!nodeId) return errorResponse(400, `\`${nodeRaw}\` is not a valid operator node id`);
    const node = this.nodes.get(nodeId);
    if (!node) return errorResponse(404, `no operator \`${nodeRaw}\``);
    const delegatedBy: Record<string, unknown>[] = [];
    const delegates: Record<string, unknown>[] = [];
    for (const e of this.edges) {
      if (e.child === nodeId) delegatedBy.push(edgeWire(e));
      else if (e.parent === nodeId) delegates.push(edgeWire(e));
    }
    const memberships: Record<string, unknown>[] = [];
    for (const [jur, list] of this.trustLists) {
      for (const entry of list.entries.values()) {
        if (entry.node === nodeId) {
          memberships.push({
            jurisdiction: jur,
            not_before: tsFormat(entry.not_before),
            superseded_at: entry.superseded_at === null ? null : tsFormat(entry.superseded_at),
            in_force_at_as_of: entryInForce(entry, at.at ?? nowSecs()),
          });
        }
      }
    }
    memberships.sort((a, b) => (String(a.jurisdiction) < String(b.jurisdiction) ? -1 : 1));
    const masterEntry = this.masterEntries.get(nodeId) ?? null;
    const asOf = this.asOfOf(at.at);
    return jsonBody(
      200,
      {
        operator: nodeId,
        kind: kindDebug(node.kind),
        keys: node.keys.map((k) => ({ key_id: k.key_id, suite: k.suite })),
        delegated_by: delegatedBy,
        delegates,
        trust_list_memberships: memberships,
        master_list: masterEntry
          ? {
              attested_by: masterEntry.attestations.length,
              witnesses: masterEntry.attestations.map((a) => a.witness),
            }
          : null,
        revocations: this.revocations
          .filter((r) => r.subject["kind"] === "node" && r.subject["id"] === nodeId)
          .map(revocationWire),
        as_of: asOf,
      },
      asOf,
      CACHE_CURRENT,
    );
  }

  private evidenceCatalogue(): Response {
    const items = [...this.evidence.values()]
      .sort((a, b) => (a.id < b.id ? -1 : 1))
      .map(evidenceMeta);
    return jsonBody(200, { count: items.length, items }, isoNow(), CACHE_CURRENT);
  }

  private async evidenceRelease(id: string, url: URL, request: Request): Promise<Response> {
    const scope = url.searchParams.get("scope") ?? request.headers.get("x-unidpp-scope") ?? "";
    const requester =
      url.searchParams.get("requester") ?? request.headers.get("x-unidpp-requester");
    const evidence = this.evidence.get(id);
    if (!evidence) return errorResponse(404, `no evidence \`${id}\``);
    if (scope !== evidence.required_scope) {
      // The refusal is stated naming the required scope — never a
      // silent 404; a denial creates no record.
      return errorResponse(
        403,
        `evidence \`${id}\` requires scope \`${evidence.required_scope}\` — the request carried \`${scope}\``,
      );
    }
    await this.record("evidence-released", { id, requester, scope });
    return new Response(evidence.content.slice(), {
      status: 200,
      headers: {
        "content-type": evidence.content_type,
        "x-as-of": isoNow(),
        "x-unidpp-scope": evidence.required_scope,
      },
    });
  }

  private adminLog(url: URL): Response {
    const limitRaw = url.searchParams.get("limit");
    const limit = Math.min(limitRaw && /^\d+$/.test(limitRaw) ? Number(limitRaw) : 100, 10_000);
    const offsetRaw = url.searchParams.get("offset");
    const offset = offsetRaw && /^\d+$/.test(offsetRaw) ? Number(offsetRaw) : 0;
    const records = this.log
      .slice(offset, offset + limit)
      .map((r) => ({ op: r.op, body: r.body, seq: r.seq, recorded_at: r.recorded_at }));
    return jsonBody(200, { total: this.log.length, offset, records }, isoNow(), CACHE_CURRENT);
  }

  // -- mutations ---------------------------------------------------------

  private async readBody(request: Request): Promise<{ parsed: unknown } | { invalid: true }> {
    try {
      return { parsed: await request.json() };
    } catch {
      return { invalid: true };
    }
  }

  private async registerNode(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return errorResponse(400, "node must be an object");
    }
    const obj = v as Record<string, unknown>;
    const idRaw = obj["id"];
    if (typeof idRaw !== "string") return errorResponse(400, "`id` is required");
    const id = nodeIdParse(idRaw);
    if (!id) return errorResponse(400, `\`id\`: ${nodeBad(idRaw)}`);
    if (obj["kind"] === undefined) return errorResponse(400, "`kind` is required");
    const kind = kindParse(obj["kind"]);
    if ("error" in kind) return errorResponse(400, kind.error);
    const keys: StoredNode["keys"] = [];
    const keysRaw = obj["keys"];
    if (Array.isArray(keysRaw)) {
      for (const k of keysRaw) {
        const entry = k as Record<string, unknown> | null;
        if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
          return errorResponse(400, "`keys[].key_id` must be an object");
        }
        const keyRaw = entry["key_id"];
        if (typeof keyRaw !== "string") return errorResponse(400, "`key_id` is required");
        const keyId = keyIdNew(keyRaw);
        if (!keyId) {
          return errorResponse(400, `\`key_id\`: validation error: bad key id \`${keyRaw}\``);
        }
        const parsed = publicParse(this.core, entry);
        if ("error" in parsed) return errorResponse(400, parsed.error);
        if (keyId !== parsed.key_id) {
          return errorResponse(
            400,
            `\`key_id\` \`${keyId}\` does not match the declared public key`,
          );
        }
        keys.push({
          key_id: keyId,
          suite: parsed.suite,
          public: parsed.public,
          public_len: parsed.public_len,
        });
      }
    }
    const node: StoredNode = { id, kind: kind.kind, keys };
    this.apply({ op: "register-node", body: node });
    const rec = await this.record("register-node", nodeWire(node));
    return jsonBody(201, { ...nodeWire(node), audit_seq: rec.seq }, isoNow(), CACHE_NO_STORE);
  }

  private async addEdge(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return errorResponse(400, "edge must be an object");
    }
    const obj = v as Record<string, unknown>;
    const parentRaw = obj["parent"];
    if (typeof parentRaw !== "string") return errorResponse(400, "`parent` is required");
    const parent = nodeIdParse(parentRaw);
    if (!parent) return errorResponse(400, `\`parent\`: ${nodeBad(parentRaw)}`);
    const childRaw = obj["child"];
    if (typeof childRaw !== "string") return errorResponse(400, "`child` is required");
    const child = nodeIdParse(childRaw);
    if (!child) return errorResponse(400, `\`child\`: ${nodeBad(childRaw)}`);
    if (obj["scope"] === undefined) return errorResponse(400, "`scope` is required");
    const signaturesRaw = obj["signatures"];
    if (!Array.isArray(signaturesRaw)) {
      return errorResponse(400, "`signatures` array is required");
    }
    const signatures: StoredSlot[] = [];
    for (const s of signaturesRaw) {
      const slot = slotParse(s);
      if ("error" in slot) return errorResponse(400, slot.error);
      signatures.push(slot.slot);
    }
    const edge: StoredEdge = {
      parent,
      child,
      scope: normalizeScope(obj["scope"]),
      signatures,
    };
    // TrustGraph::add_edge's validations: known endpoints, no
    // contradictory scope, a signed credential, and the DAG
    // invariant. (Signature validity is resolution's concern, not
    // insertion's — the same posture as the native store.)
    if (!this.nodes.has(parent)) return errorResponse(400, `unknown node \`${parent}\``);
    if (!this.nodes.has(child)) return errorResponse(400, `unknown node \`${child}\``);
    if (scopeContradiction(edge.scope)) {
      return errorResponse(
        400,
        `scope violation: credential ${parent} -> ${child} carries a contradictory scope`,
      );
    }
    if (signatures.length === 0) {
      return errorResponse(
        400,
        `delegation credential ${parent} -> ${child} failed signature verification`,
      );
    }
    if (this.reaches(child, parent)) {
      return errorResponse(
        400,
        `validation error: edge ${parent} -> ${child} would close a cycle (trust graph must stay a DAG)`,
      );
    }
    this.edges.push(edge);
    const rec = await this.record("add-edge", edgeWire(edge));
    return jsonBody(201, { ...edgeWire(edge), audit_seq: rec.seq }, isoNow(), CACHE_NO_STORE);
  }

  // The DAG check: whether `from` reaches `to` over the delegation
  // edges (child-to-parent reachability closes a cycle).
  private reaches(from: string, to: string): boolean {
    const seen = new Set<string>();
    const stack = [from];
    while (stack.length > 0) {
      const n = stack.pop() as string;
      if (n === to) return true;
      if (seen.has(n)) continue;
      seen.add(n);
      for (const e of this.edges) {
        if (e.parent === n) stack.push(e.child);
      }
    }
    return false;
  }

  private async registerTrustList(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed as Record<string, unknown>;
    const jurRaw = v["jurisdiction"];
    if (typeof jurRaw !== "string" || !jurRaw.trim()) {
      return errorResponse(400, "`jurisdiction` is required");
    }
    const jurisdiction = jurRaw.trim();
    if (
      jurisdiction.length > 256 ||
      jurisdiction.includes("/") ||
      /\s/.test(jurisdiction)
    ) {
      return errorResponse(
        400,
        "`jurisdiction` must be 1-256 characters without `/` or whitespace",
      );
    }
    const frameworkRaw = v["framework"];
    const framework =
      typeof frameworkRaw === "string" && frameworkRaw.trim() !== "" ? frameworkRaw.trim() : null;
    const key = jurisdiction.toUpperCase();
    if (this.trustLists.has(key)) {
      return errorResponse(409, `trust list \`${jurisdiction}\` is already registered`);
    }
    const rec = await this.record("register-trust-list", { jurisdiction, framework });
    this.apply({ op: "register-trust-list", body: { jurisdiction, framework } });
    // Optional initial entries — applied after the list is registered.
    const entriesRaw = v["entries"];
    if (Array.isArray(entriesRaw)) {
      for (const entryV of entriesRaw) {
        const parsed = trustEntryParse(entryV);
        if ("error" in parsed) return errorResponse(400, parsed.error);
        const list = this.trustLists.get(key);
        if (!list) return errorResponse(404, `no trust list \`${jurisdiction}\``);
        this.applyEntry(list, parsed.entry);
        await this.record("upsert-trust-entry", {
          jurisdiction,
          node: parsed.entry.node,
          not_before: tsFormat(parsed.entry.not_before),
          superseded_at:
            parsed.entry.superseded_at === null ? null : tsFormat(parsed.entry.superseded_at),
        });
      }
    }
    return jsonBody(
      201,
      {
        jurisdiction: jurisdiction.toUpperCase(),
        framework,
        audit_seq: rec.seq,
        as_of: isoNow(),
      },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  private async upsertTrustEntry(jur: string, request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const parsed = trustEntryParse(read.parsed);
    if ("error" in parsed) return errorResponse(400, parsed.error);
    const list = this.trustLists.get(jur.toUpperCase());
    if (!list) return errorResponse(404, `no trust list \`${jur}\``);
    const entry = parsed.entry;
    this.applyEntry(list, entry);
    const rec = await this.record("upsert-trust-entry", {
      jurisdiction: jur,
      node: entry.node,
      not_before: tsFormat(entry.not_before),
      superseded_at: entry.superseded_at === null ? null : tsFormat(entry.superseded_at),
    });
    return jsonBody(
      201,
      {
        jurisdiction: jur,
        node: entry.node,
        not_before: tsFormat(entry.not_before),
        superseded_at: entry.superseded_at === null ? null : tsFormat(entry.superseded_at),
        audit_seq: rec.seq,
        as_of: isoNow(),
      },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  private async setWitnesses(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const obj = read.parsed as Record<string, unknown>;
    const mRaw = obj["m"];
    if (typeof mRaw !== "number" || !Number.isInteger(mRaw)) {
      return errorResponse(400, "`m` (number >= 1) is required");
    }
    const witnessesRaw = obj["witnesses"];
    if (!Array.isArray(witnessesRaw)) {
      return errorResponse(400, "`witnesses` array is required");
    }
    const witnesses: StoredWitness[] = [];
    for (const w of witnessesRaw) {
      const entry = w as Record<string, unknown> | null;
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return errorResponse(400, "witness must be an object");
      }
      const nodeRaw = entry["node"];
      if (typeof nodeRaw !== "string") return errorResponse(400, "`node` is required");
      const node = nodeIdParse(nodeRaw);
      if (!node) return errorResponse(400, `\`node\`: ${nodeBad(nodeRaw)}`);
      const parsed = publicParse(this.core, entry);
      if ("error" in parsed) return errorResponse(400, parsed.error);
      witnesses.push({
        node,
        suite: parsed.suite,
        key_id: parsed.key_id,
        public: parsed.public,
        public_len: parsed.public_len,
      });
    }
    if (mRaw === 0) return errorResponse(400, "`m` must be >= 1");
    if (witnesses.length === 0) return errorResponse(400, "`witnesses` must be non-empty");
    if (mRaw > witnesses.length) {
      return errorResponse(
        400,
        `\`m\` (${mRaw}) cannot exceed \`witnesses.len()\` (${witnesses.length})`,
      );
    }
    const body = { m: mRaw, witnesses };
    this.apply({ op: "set-witnesses", body });
    const rec = await this.record("set-witnesses", {
      m: mRaw,
      witnesses: witnesses.map((w) => ({
        node: w.node,
        suite: w.suite,
        public: w.public,
        public_len: w.public_len,
      })),
    });
    return jsonBody(
      201,
      {
        m: mRaw,
        k: witnesses.length,
        witnesses: witnesses.map(witnessWire),
        audit_seq: rec.seq,
        as_of: isoNow(),
      },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  private async upsertMasterEntry(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return errorResponse(400, "master-list entry must be an object");
    }
    const obj = v as Record<string, unknown>;
    const nodeRaw = obj["node"];
    if (typeof nodeRaw !== "string") return errorResponse(400, "`node` is required");
    const node = nodeIdParse(nodeRaw);
    if (!node) return errorResponse(400, `\`node\`: ${nodeBad(nodeRaw)}`);
    const attestationsRaw = obj["attestations"];
    if (!Array.isArray(attestationsRaw)) {
      return errorResponse(400, "`attestations` array is required");
    }
    const attestations: StoredAttestation[] = [];
    for (const a of attestationsRaw) {
      const entry = a as Record<string, unknown> | null;
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return errorResponse(400, "witness attestation must be an object");
      }
      const witnessRaw = entry["witness"];
      if (typeof witnessRaw !== "string") return errorResponse(400, "`witness` is required");
      const witness = nodeIdParse(witnessRaw);
      if (!witness) return errorResponse(400, `\`witness\`: ${nodeBad(witnessRaw)}`);
      const atRaw = entry["at"];
      if (typeof atRaw !== "string") return errorResponse(400, "`at` (RFC 3339) is required");
      const atSecs = tsParse(atRaw);
      if (atSecs === null) return errorResponse(400, tsBad(atRaw));
      if (entry["slot"] === undefined) return errorResponse(400, "`slot` is required");
      const slot = slotParse(entry["slot"]);
      if ("error" in slot) return errorResponse(400, slot.error);
      attestations.push({ witness, at: tsFormat(atSecs), slot: slot.slot });
    }
    const entry: StoredMasterEntry = { node, attestations };
    for (const att of attestations) {
      if (!this.witnesses.has(att.witness)) {
        return errorResponse(400, `witness \`${att.witness}\` is not registered`);
      }
    }
    this.masterEntries.set(node, entry);
    const rec = await this.record("upsert-master-entry", masterEntryWire(entry));
    return jsonBody(
      201,
      { node, attestations: masterEntryWire(entry).attestations, audit_seq: rec.seq, as_of: isoNow() },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  private async declareRevocation(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return errorResponse(400, "revocation must be an object");
    }
    const obj = v as Record<string, unknown>;
    if (obj["subject"] === undefined) return errorResponse(400, "`subject` is required");
    const subject = subjectParse(obj["subject"]);
    if ("error" in subject) return errorResponse(400, subject.error);
    if (obj["reason"] === undefined) return errorResponse(400, "`reason` is required");
    const reason = reasonParse(obj["reason"]);
    if ("error" in reason) return errorResponse(400, reason.error);
    const declaredRaw = obj["declared_at"];
    if (typeof declaredRaw !== "string") {
      return errorResponse(400, "`declared_at` (RFC 3339) is required");
    }
    const declaredAt = tsParse(declaredRaw);
    if (declaredAt === null) return errorResponse(400, tsBad(declaredRaw));
    const byRaw = obj["declared_by"];
    if (typeof byRaw !== "string") return errorResponse(400, "`declared_by` is required");
    const declaredBy = nodeIdParse(byRaw);
    if (!declaredBy) return errorResponse(400, `\`declared_by\`: ${nodeBad(byRaw)}`);
    if (obj["window"] === undefined) return errorResponse(400, "`window` is required");
    const window = windowParse(obj["window"]);
    if ("error" in window) return errorResponse(400, window.error);
    let quorum: StoredRevocation["quorum"] = null;
    const quorumRaw = obj["quorum"];
    if (quorumRaw !== undefined && quorumRaw !== null) {
      const entry = quorumRaw as Record<string, unknown> | null;
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        return errorResponse(400, "quorum attestation must be an object");
      }
      const quorumNodeRaw = entry["quorum"];
      if (typeof quorumNodeRaw !== "string") return errorResponse(400, "`quorum` is required");
      const quorumNode = nodeIdParse(quorumNodeRaw);
      if (!quorumNode) {
        return errorResponse(400, `\`quorum\`: ${nodeBad(quorumNodeRaw)}`);
      }
      const threshold = entry["threshold"];
      if (typeof threshold !== "number") {
        return errorResponse(400, "`threshold` (number) is required");
      }
      const signaturesRaw = entry["signatures"];
      if (!Array.isArray(signaturesRaw)) {
        return errorResponse(400, "`signatures` array is required");
      }
      const signatures: StoredSlot[] = [];
      for (const s of signaturesRaw) {
        const slot = slotParse(s);
        if ("error" in slot) return errorResponse(400, slot.error);
        signatures.push(slot.slot);
      }
      quorum = { quorum: quorumNode, threshold, signatures };
    }
    // Retroactive distrust is authority-over-authority: without a
    // quorum attestation the declaration refuses on the merits (422),
    // and with one present the Quorum-domain slots verify against the
    // graph before recording — the native's intake verification, the
    // refusal texts verbatim.
    if (reason.retroactive && quorum === null) {
      return errorResponse(
        422,
        `retroactive distrust of \`${subject.label}\` requires a quorum attestation`,
      );
    }
    if (reason.retroactive && quorum !== null) {
      const verdict = this.quorumVerdictOf(quorum, {
        label: subject.label,
        reasonToken: String(reason.reason.token),
        declaredBy: declaredBy,
        windowStart: window.start,
        windowEnd: window.end,
      });
      if (!verdict.quorate) {
        const summary =
          verdict.form === "threshold-group"
            ? `threshold-group signature verified (${quorum.threshold} of the group's members acted), threshold ${quorum.threshold}`
            : `${verdict.verified_count} member key(s) verified, threshold ${quorum.threshold}`;
        return errorResponse(
          422,
          `quorum attestation for \`${subject.label}\` does not reach the threshold (${summary})`,
        );
      }
    }
    const revocation: StoredRevocation = {
      subject: subject.subject,
      label: subject.label,
      reason: reason.reason,
      retroactive: reason.retroactive,
      declared_at: declaredAt,
      declared_at_text: tsFormat(declaredAt),
      declared_by: declaredBy,
      window: {
        start: tsFormat(window.start),
        end: window.end === null ? null : tsFormat(window.end),
        open: window.end === null,
      },
      window_start: window.start,
      window_end: window.end,
      quorum,
    };
    this.revocations.push(revocation);
    const rec = await this.record("declare-revocation", revocationWire(revocation));
    return jsonBody(
      201,
      {
        subject: revocation.subject,
        reason: revocation.reason,
        declared_at: revocation.declared_at_text,
        declared_by: revocation.declared_by,
        window: revocation.window,
        audit_seq: rec.seq,
        as_of: isoNow(),
      },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  private async registerEvidence(request: Request): Promise<Response> {
    const read = await this.readBody(request);
    if ("invalid" in read) return errorResponse(400, "invalid JSON body");
    const v = read.parsed;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return errorResponse(400, "body must be a JSON object");
    }
    const obj = v as Record<string, unknown>;
    const idRaw = obj["id"];
    if (typeof idRaw !== "string" || !idRaw.trim()) {
      return errorResponse(400, "`id` is required");
    }
    const scopeRaw = obj["requiredScope"];
    if (typeof scopeRaw !== "string" || !scopeRaw.trim()) {
      return errorResponse(
        400,
        "`requiredScope` is required — ungated evidence is a public link, not evidence",
      );
    }
    const hexRaw = obj["contentHex"];
    if (typeof hexRaw !== "string") return errorResponse(400, "`contentHex` is required");
    const decoded = hexDecode(hexRaw);
    if ("error" in decoded) return errorResponse(400, `\`contentHex\`: ${decoded.error}`);
    if (decoded.bytes.length === 0) {
      return errorResponse(400, "`content_hex` must not be empty");
    }
    const typeRaw = obj["contentType"];
    const descRaw = obj["description"];
    const evidence: StoredEvidence = {
      id: idRaw,
      content_type: typeof typeRaw === "string" ? typeRaw : "application/octet-stream",
      description: typeof descRaw === "string" ? descRaw : "",
      required_scope: scopeRaw,
      content: decoded.bytes,
    };
    if (this.evidence.has(evidence.id)) {
      return errorResponse(409, `evidence \`${evidence.id}\` is already registered`);
    }
    this.evidence.set(evidence.id, evidence);
    const rec = await this.record("register-evidence", {
      id: evidence.id,
      content_type: evidence.content_type,
      description: evidence.description,
      required_scope: evidence.required_scope,
      content_hex: hex(evidence.content),
    });
    return jsonBody(
      201,
      { ...evidenceMeta(evidence), audit_seq: rec.seq },
      isoNow(),
      CACHE_NO_STORE,
    );
  }

  // Verify a signed tree head against the served anchor: the third
  // party's F1 path, byte-for-byte the native verification's inputs
  // (the canonical bytes are built inside the wasm boundary).
  private async verify(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return new Response(JSON.stringify({ error: "invalid JSON body" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const treeHead = v.tree_head as
      | {
          log_id: string;
          tree_size: number;
          timestamp: string;
          root: string;
          signature: { signature: string };
        }
      | undefined;
    if (!treeHead?.log_id || !treeHead.tree_size || !treeHead.root || !treeHead.signature) {
      return new Response(JSON.stringify({ error: "`tree_head` is required" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const ms = Date.parse(treeHead.timestamp);
    const secs = Math.floor(ms / 1000);
    const nanos = (ms % 1000) * 1_000_000;
    const core = this.core;
    const anchor = this.anchorOf();
    const publicPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, publicPtr, 32).set(unhex(anchor.public));
    const logBytes = new TextEncoder().encode(treeHead.log_id);
    const logPtr = core.unidpp_alloc(logBytes.length);
    new Uint8Array(core.memory.buffer, logPtr, logBytes.length).set(logBytes);
    const rootPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, rootPtr, 32).set(unhex(treeHead.root));
    const sigPtr = core.unidpp_alloc(64);
    new Uint8Array(core.memory.buffer, sigPtr, 64).set(unhex(treeHead.signature.signature));
    const rc = core.unidpp_sth_verify(
      publicPtr,
      logPtr,
      logBytes.length,
      BigInt(treeHead.tree_size),
      BigInt(secs),
      nanos,
      rootPtr,
      sigPtr,
    );
    [publicPtr, logPtr, rootPtr, sigPtr].forEach((ptr, i) =>
      core.unidpp_free(ptr, [32, logBytes.length, 32, 64][i]),
    );
    return new Response(
      JSON.stringify({
        verified: rc === 1,
        anchor: { key_id: anchor.key_id, suite: anchor.suite },
        log_id: treeHead.log_id,
        tree_size: treeHead.tree_size,
      }),
      { headers: { "content-type": "application/json", "x-as-of": new Date().toISOString() } },
    );
  }
}
