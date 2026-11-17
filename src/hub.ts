// The translation hub on the estate (REARCH R12 S5): a stateless
// signed relay between willing pairs divided by protocols. The relay
// core and the declaration issuance are the signatif crate's own —
// willingness both ways (a scheme that declines is never brokered
// around; the absent declaration is stated), the canonical payload,
// the HUB-RELAY signature through the wasm boundary. The hub holds
// nothing: after the relay the state is gone. The discovery document
// and the keyring (the relay role's public anchor, under which every
// relay signature verifies) ride beside the relay, exactly as the
// native hub serves them; the verification endpoint answers both the
// native form (POST /relay/verify) and the doubled form the estate
// router forwards (POST /relay/relay/verify).

import { workerCore } from "./mount";

const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

// The hub's identity: the native Config's default hub id, the same
// value the relay signs and the discovery document states.
const HUB_ID = "unidpp-hub-1";

// The hub answers with the native json_response's conventions: the
// as-of stamp rides every response's header.
const stampHeaders = (): Record<string, string> => ({
  "content-type": "application/json",
  "x-as-of": new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
});

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }, null, 2), {
    status: 400,
    headers: stampHeaders(),
  });

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: stampHeaders(),
  });

// The axum method fallback: an empty 405 naming the served method.
const methodNotAllowed = (): Response =>
  new Response(null, { status: 405, headers: { allow: "POST" } });

interface RelayRequest {
  hub_id?: string;
  evidence_hex: string;
  from: string;
  to: string;
  data_class: string;
  declarations: unknown;
}

// The note buffer contract: the core's last JSON document (a relayed
// evidence, an issued declaration, or a refusal).
function takeNote(core: ReturnType<typeof workerCore>): string {
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const text =
    noteLen > 0
      ? new TextDecoder().decode(new Uint8Array(core.memory.buffer, notePtr, noteLen).slice())
      : "";
  core.unidpp_free(notePtr, 1048576);
  return text;
}

export interface Posture {
  data_class: string;
  level: string;
  recognition: string;
  transports: string[];
  escalation?: string;
  reciprocity?: string;
}

// Issue a declaration through the wasm boundary: signatif's own
// `InteropDeclaration::issue` signs the canonical bytes in the
// INTEROP-DECLARATION domain with the seed-derived key.
export function issueDeclaration(input: {
  declarer: string;
  counterpart: string;
  version: number;
  postures: Posture[];
  valid_from: string;
  valid_to?: string;
}): { ok: true; declaration: Record<string, unknown> } | { ok: false; error: string } {
  const core = workerCore();
  const encoder = new TextEncoder();
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = encoder.encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const seed = unhex(sha256Label(core, "UNIDPP-HUB/OPERATOR-SEED"));
  const seedPtr = core.unidpp_alloc(32);
  new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
  const declarer = put(input.declarer);
  const counterpart = put(input.counterpart);
  const postures = put(JSON.stringify(input.postures));
  const validFrom = put(input.valid_from);
  const validTo = put(input.valid_to ?? "");
  const rc = core.unidpp_declaration_issue(
    seedPtr,
    declarer.ptr,
    declarer.len,
    counterpart.ptr,
    counterpart.len,
    BigInt(input.version),
    postures.ptr,
    postures.len,
    validFrom.ptr,
    validFrom.len,
    validTo.ptr,
    validTo.len,
  );
  [seedPtr, declarer.ptr, counterpart.ptr, postures.ptr, validFrom.ptr, validTo.ptr].forEach(
    (ptr, i) => core.unidpp_free(ptr, [32, declarer.len, counterpart.len, postures.len, validFrom.len, validTo.len][i]),
  );
  const note = takeNote(core);
  if (rc === 0) {
    return { ok: true, declaration: JSON.parse(note) as Record<string, unknown> };
  }
  return { ok: false, error: note || `the issuance failed (${rc})` };
}

function sha256Bytes(core: ReturnType<typeof workerCore>, data: Uint8Array): Uint8Array {
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  const value = out.slice();
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return value;
}

function sha256Label(core: ReturnType<typeof workerCore>, label: string): string {
  const bytes = new TextEncoder().encode(label);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, bytes.length, outPtr);
  const value = hex(out);
  core.unidpp_free(ptr, bytes.length);
  core.unidpp_free(outPtr, 32);
  return value;
}

// ---------------------------------------------------------------------------
// The native body guards: the strict deserialization the native hub's
// axum `Json` extractors perform, with serde's own messages. A body
// that is not JSON answers the parse rejection (400); a body missing a
// required field or carrying a mistyped one answers the
// deserialization rejection (422), naming the field, the expected type
// and the position.
// ---------------------------------------------------------------------------

const lineCol = (text: string, idx: number): string => {
  let line = 1;
  let col = 1;
  for (let i = 0; i < idx && i < text.length; i++) {
    if (text[i] === "\n") {
      line += 1;
      col = 1;
    } else {
      col += 1;
    }
  }
  return `line ${line} column ${col}`;
};

// The matching close of the container opening at `open` (string-aware).
function matchingClose(text: string, open: number): number {
  const pairs: Record<string, string> = { "{": "}", "[": "]" };
  const close = pairs[text[open]] ?? "}";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{" || ch === "[") depth += 1;
    else if (ch === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return text.length - 1;
}

// The value span of `name` inside the object opening at `open`
// (0-based, end exclusive), or null when the key is absent.
function fieldValueSpan(
  text: string,
  open: number,
  name: string,
): { start: number; end: number } | null {
  const key = `"${name}"`;
  const bound = matchingClose(text, open);
  let at = text.indexOf(key, open + 1);
  while (at !== -1 && at < bound) {
    let cursor = at + key.length;
    while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1;
    if (text[cursor] === ":") {
      cursor += 1;
      while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1;
      const from = cursor;
      if (text[cursor] === '"') {
        cursor += 1;
        while (cursor < text.length) {
          if (text[cursor] === "\\") cursor += 1;
          else if (text[cursor] === '"') break;
          cursor += 1;
        }
        cursor += 1;
      } else if (text[cursor] === "{" || text[cursor] === "[") {
        cursor = matchingClose(text, cursor) + 1;
      } else {
        while (
          cursor < text.length &&
          !/[,\s}\]]/.test(text[cursor])
        )
          cursor += 1;
      }
      return { start: from, end: cursor };
    }
    at = text.indexOf(key, at + key.length);
  }
  return null;
}

type FieldSpec =
  | { name: string; expect: "string" }
  | { name: string; expect: "object"; expected: string }
  | { name: string; expect: "array"; length: number };

// serde's name for the value it found.
function serdeTypeName(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? `integer \`${value}\``
      : `floating point \`${value}\``;
  }
  if (typeof value === "string") return `string "${value}"`;
  if (typeof value === "boolean") return `boolean \`${value}\``;
  if (Array.isArray(value)) return "sequence";
  return "map";
}

// The strict field guard over one object (the root, or a nested
// struct named by `prefix`). Returns the first rejection text, or
// null when every declared field is present and well typed.
function guardFields(
  text: string,
  open: number,
  value: Record<string, unknown>,
  spec: FieldSpec[],
  prefix = "",
): string | null {
  const fieldPath = (name: string): string => (prefix ? `${prefix}.${name}` : name);
  const parentPath = prefix;
  for (const field of spec) {
    const present = Object.prototype.hasOwnProperty.call(value, field.name);
    const span = fieldValueSpan(text, open, field.name);
    if (!present || !span) {
      return `Failed to deserialize the JSON body into the target type: ${
        parentPath ? `${parentPath}: ` : ""
      }missing field \`${field.name}\` at ${lineCol(text, matchingClose(text, open))}`;
    }
    const found = value[field.name];
    if (field.expect === "string") {
      if (typeof found !== "string") {
        return `Failed to deserialize the JSON body into the target type: ${fieldPath(
          field.name,
        )}: invalid type: ${serdeTypeName(found)}, expected a string at ${lineCol(text, span.end - 1)}`;
      }
    } else if (field.expect === "object") {
      if (found === null || typeof found !== "object" || Array.isArray(found)) {
        return `Failed to deserialize the JSON body into the target type: ${fieldPath(
          field.name,
        )}: invalid type: ${serdeTypeName(found)}, expected ${field.expected} at ${lineCol(
          text,
          span.end - 1,
        )}`;
      }
    } else {
      if (!Array.isArray(found)) {
        return `Failed to deserialize the JSON body into the target type: ${fieldPath(
          field.name,
        )}: invalid type: ${serdeTypeName(found)}, expected an array of length ${
          field.length
        } at ${lineCol(text, span.end - 1)}`;
      }
      if (found.length !== field.length) {
        return `Failed to deserialize the JSON body into the target type: ${fieldPath(
          field.name,
        )}: invalid length ${found.length}, expected an array of length ${
          field.length
        } at ${lineCol(text, span.end - 1)}`;
      }
    }
  }
  return null;
}

// serde_json's parse rejection for the malformed bodies (the native
// Json extractor's 400; the deterministic shapes are emulated).
const serdeParseError = (text: string): string => {
  const t = text.trim();
  if (t === "") return "EOF while parsing a value at line 1 column 0";
  const head = t[0];
  if (head === "n" || head === "t" || head === "f")
    return "expected ident at line 1 column 2";
  return "expected value at line 1 column 1";
};

// Parse the request body the way the native extractors do: the parse
// rejection first, then the strict field guard.
function readStrict(
  body: string,
  spec: FieldSpec[],
): { ok: true; value: Record<string, unknown> } | { ok: false; response: Response } {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    return {
      ok: false,
      response: new Response(
        `Failed to parse the request body as JSON: ${serdeParseError(body)}`,
        { status: 400, headers: { "content-type": "text/plain; charset=utf-8" } },
      ),
    };
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return {
      ok: false,
      response: new Response(
        `Failed to deserialize the JSON body into the target type: invalid type: ${serdeTypeName(
          value,
        )}, expected struct RelayRequest at ${lineCol(body, body.trimEnd().length - 1)}`,
        { status: 422, headers: { "content-type": "text/plain; charset=utf-8" } },
      ),
    };
  }
  const record = value as Record<string, unknown>;
  const rejection = guardFields(body, body.indexOf("{"), record, spec);
  if (rejection) {
    return {
      ok: false,
      response: new Response(rejection, {
        status: 422,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
    };
  }
  return { ok: true, value: record };
}

const decodeEvidence = (raw: string): { ok: true; bytes: Uint8Array } | { ok: false; reason: string } => {
  const trimmed = raw.trim();
  if (!/^[0-9a-fA-F]*$/.test(trimmed)) return { ok: false, reason: "not hex" };
  if (trimmed.length % 2 !== 0) return { ok: false, reason: "not hex (odd length)" };
  return { ok: true, bytes: unhex(trimmed) };
};

// The relay payload the hub signs (signatif's Hub::relay_payload):
// the canonical writer's length-framed hub id, evidence digest,
// endpoints and class.
function relayPayload(
  core: ReturnType<typeof workerCore>,
  hubId: string,
  evidence: Uint8Array,
  from: string,
  to: string,
  dataClass: string,
): Uint8Array {
  const encoder = new TextEncoder();
  const digest = sha256Bytes(core, evidence);
  const frame = (text: string): Uint8Array => {
    const bytes = encoder.encode(text);
    const out = new Uint8Array(4 + bytes.length);
    new DataView(out.buffer).setUint32(0, bytes.length, true);
    out.set(bytes, 4);
    return out;
  };
  const parts = [
    frame(hubId),
    (() => {
      const out = new Uint8Array(4 + digest.length);
      new DataView(out.buffer).setUint32(0, digest.length, true);
      out.set(digest, 4);
      return out;
    })(),
    frame(from),
    frame(to),
    frame(dataClass),
  ];
  const total = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// The hub's public key (the seed-derived operator key the relay
// signatures verify under).
function hubPublic(core: ReturnType<typeof workerCore>): Uint8Array {
  const seed = unhex(sha256Label(core, "UNIDPP-HUB/OPERATOR-SEED"));
  const seedPtr = core.unidpp_alloc(32);
  new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
  const outPtr = core.unidpp_alloc(32);
  core.unidpp_head_public(seedPtr, outPtr);
  const publicBytes = new Uint8Array(core.memory.buffer, outPtr, 32).slice();
  core.unidpp_free(seedPtr, 32);
  core.unidpp_free(outPtr, 32);
  return publicBytes;
}

// The discovery document (the family convention): service identity,
// hub id, endpoint map and the contract statements.
function discoveryDocument(): Record<string, unknown> {
  return {
    contract: [
      "stateless: no storage, no journals, no posture state — the caller carries the declarations",
      "willingness both ways: a scheme that declines interop is never brokered around (the WILL gap is not the hub's to bridge)",
      "signed: every relay is signed in the HUB-RELAY domain over the forwarded bytes plus the relay metadata",
      "no master: a pair that speaks directly has no need of the hub; no message of the protocol names one",
    ],
    description:
      "UniDPP translation hub: a stateless signed relay between willing pairs divided by protocols (the SI-3 hub contract)",
    endpoints: {
      health: "GET /healthz",
      keyring: "GET /keyring — the hub's public key (relay signatures verify under it)",
      relay:
        "POST /relay {from, to, data_class, evidence_hex, declarations: [..]} — both sides' published declarations ride the request; willingness is checked both ways, the forwarded bytes are signed in the HUB-RELAY domain, nothing is retained",
      relay_verify:
        "POST /relay/verify {evidence_hex, relay: {..}} — verify a relay under this hub's key",
    },
    hub_id: HUB_ID,
    service: "unidpp-hub",
  };
}

// GET /relay — the discovery document.
export function discovery(_request: Request): Response {
  return json(200, discoveryDocument());
}

// GET /relay/keyring — the relay role's suite and public key, under
// which every relay signature verifies.
export function keyring(_request: Request): Response {
  const core = workerCore();
  return json(200, {
    mode: "seeded-dev",
    roles: {
      relay: {
        public_hex: hex(hubPublic(core)),
        suite: "ed25519",
      },
    },
  });
}

// POST /relay/relay/verify — the estate's doubled forward of the
// native POST /relay/verify: verify a relayed evidence under this
// hub's key. The bare native form answers identically.
async function relayVerify(request: Request): Promise<Response> {
  const core = workerCore();
  const body = await request.text();
  const read = readStrict(body, [
    { name: "evidence_hex", expect: "string" },
    { name: "relay", expect: "object", expected: "struct RelayedEvidence" },
  ]);
  if (!read.ok) return read.response;
  const envelope = read.value.relay as Record<string, unknown>;
  // The nested RelayedEvidence guard (the native struct's field
  // order; the rejection names the parent struct and the nested
  // object's own closing brace).
  const relaySpan = fieldValueSpan(body, body.indexOf("{"), "relay");
  const relayOpen = relaySpan ? body.indexOf("{", relaySpan.start) : body.indexOf("{");
  const nested = guardFields(body, relayOpen, envelope, [
    { name: "hub_id", expect: "string" },
    { name: "from", expect: "string" },
    { name: "to", expect: "string" },
    { name: "data_class", expect: "string" },
    { name: "evidence_digest", expect: "array", length: 32 },
    { name: "signature", expect: "object", expected: "struct SignatureSlot" },
  ], "relay");
  if (nested) {
    return new Response(nested, {
      status: 422,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  const evidence = decodeEvidence(read.value.evidence_hex as string);
  if (!evidence.ok) return badRequest(`\`evidence_hex\`: ${evidence.reason}`);
  const relay = envelope as {
    hub_id: string;
    from: string;
    to: string;
    data_class: string;
    evidence_digest: number[];
    signature: { suite?: string; key_id?: string; signature?: number[] };
  };
  // The signature slot's own guard: suite and key_id are required,
  // the value array (when present) is the 64-byte ed25519 length.
  const sigSpan = fieldValueSpan(body, relayOpen, "signature");
  const sigOpen = sigSpan ? body.indexOf("{", sigSpan.start) : relayOpen;
  const sig = { ...relay.signature };
  const slotRejection = guardFields(
    body,
    sigOpen,
    sig as Record<string, unknown>,
    [
      { name: "suite", expect: "string" },
      { name: "key_id", expect: "string" },
    ],
    "relay.signature",
  );
  if (!slotRejection && sig.signature !== undefined) {
    const value = sig.signature;
    const span = fieldValueSpan(body, sigOpen, "signature");
    if (!Array.isArray(value)) {
      return new Response(
        `Failed to deserialize the JSON body into the target type: relay.signature.signature: invalid type: ${serdeTypeName(
          value,
        )}, expected an array of length 64 at ${lineCol(body, span ? span.end - 1 : 0)}`,
        { status: 422, headers: { "content-type": "text/plain; charset=utf-8" } },
      );
    }
    if (value.length !== 64) {
      return new Response(
        `Failed to deserialize the JSON body into the target type: relay.signature.signature: invalid length ${value.length}, expected an array of length 64 at ${lineCol(
          body,
          span ? span.end - 1 : 0,
        )}`,
        { status: 422, headers: { "content-type": "text/plain; charset=utf-8" } },
      );
    }
  }
  if (slotRejection) {
    return new Response(slotRejection, {
      status: 422,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  const payload = relayPayload(
    core,
    relay.hub_id,
    evidence.bytes,
    relay.from,
    relay.to,
    relay.data_class,
  );
  const publicBytes = hubPublic(core);
  const signature = Uint8Array.from(relay.signature.signature ?? []);
  const suite = relay.signature.suite ?? "ed25519";
  const payloadPtr = core.unidpp_alloc(payload.length);
  new Uint8Array(core.memory.buffer, payloadPtr, payload.length).set(payload);
  const publicPtr = core.unidpp_alloc(publicBytes.length);
  new Uint8Array(core.memory.buffer, publicPtr, publicBytes.length).set(publicBytes);
  const sigPtr = core.unidpp_alloc(Math.max(signature.length, 1));
  new Uint8Array(core.memory.buffer, sigPtr, signature.length).set(signature);
  const domainBytes = new TextEncoder().encode("hub-relay");
  const domainPtr = core.unidpp_alloc(domainBytes.length);
  new Uint8Array(core.memory.buffer, domainPtr, domainBytes.length).set(domainBytes);
  const suiteBytes = new TextEncoder().encode(suite);
  const suitePtr = core.unidpp_alloc(suiteBytes.length);
  new Uint8Array(core.memory.buffer, suitePtr, suiteBytes.length).set(suiteBytes);
  const rc = core.unidpp_verify_raw(
    domainPtr,
    domainBytes.length,
    suitePtr,
    suiteBytes.length,
    publicPtr,
    publicBytes.length,
    payloadPtr,
    payload.length,
    sigPtr,
    signature.length,
  );
  [domainPtr, suitePtr, publicPtr, payloadPtr, sigPtr].forEach((ptr, i) =>
    core.unidpp_free(ptr, [domainBytes.length, suiteBytes.length, publicBytes.length, payload.length, signature.length][i]),
  );
  if (rc === 1) {
    return json(200, {
      evidence_digest: hex(Uint8Array.from(relay.evidence_digest)),
      verified: true,
    });
  }
  if (rc === 0) {
    // The slot's own refusal texts (the native SignatureSlot::verify
    // errors): the framed-only placeholder, the framing budget, the
    // invalid value.
    const error =
      sig.signature === undefined
        ? "cryptographic error: slot is framed-only (nothing to verify)"
        : sig.signature.length !== 64
          ? `cryptographic error: signature length ${sig.signature.length} does not match the ed25519 framing budget 64`
          : "cryptographic error: Ed25519 signature invalid";
    return json(200, { error, verified: false });
  }
  // A shape error (an unknown suite token) states itself; the
  // deferred suites are a native-verifier matter.
  return json(200, {
    error: `suite \`${suite}\` is not verifiable at the edge`,
    verified: false,
  });
}

export const relay = (request: Request): Promise<Response> => {
  const pathname = new URL(request.url).pathname;
  if (pathname.endsWith("/verify")) {
    if (request.method !== "POST") return Promise.resolve(methodNotAllowed());
    return relayVerify(request);
  }
  return (async () => {
    if (request.method !== "POST") return methodNotAllowed();
    const core = workerCore();
    const body = await request.text();
    const read = readStrict(body, [
      { name: "from", expect: "string" },
      { name: "to", expect: "string" },
      { name: "data_class", expect: "string" },
      { name: "evidence_hex", expect: "string" },
    ]);
    if (!read.ok) return read.response;
    const v = read.value as unknown as RelayRequest;
    const evidence = decodeEvidence(v.evidence_hex);
    if (!evidence.ok) return badRequest(`\`evidence_hex\`: ${evidence.reason}`);
    const encoder = new TextEncoder();
    const put = (text: string): { ptr: number; len: number } => {
      const bytes = encoder.encode(text);
      const ptr = core.unidpp_alloc(bytes.length);
      new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
      return { ptr, len: bytes.length };
    };
    const hubId = put(v.hub_id ?? HUB_ID);
    const from = put(v.from ?? "");
    const to = put(v.to ?? "");
    const dataClass = put(v.data_class ?? "");
    const declarations = put(JSON.stringify(v.declarations ?? { declarations: [] }));
    const evidenceBuf = put("");
    // The evidence bytes land in a buffer the core reads in place.
    new Uint8Array(core.memory.buffer, evidenceBuf.ptr, evidence.bytes.length).set(evidence.bytes);
    const evidencePart = { ptr: evidenceBuf.ptr, len: evidence.bytes.length };
    void evidenceBuf;
    const seed = unhex(sha256Label(core, "UNIDPP-HUB/OPERATOR-SEED"));
    const seedPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
    const rc = core.unidpp_hub_relay(
      hubId.ptr,
      hubId.len,
      evidencePart.ptr,
      evidencePart.len,
      from.ptr,
      from.len,
      to.ptr,
      to.len,
      dataClass.ptr,
      dataClass.len,
      seedPtr,
      declarations.ptr,
      declarations.len,
    );
    [hubId.ptr, evidencePart.ptr, from.ptr, to.ptr, dataClass.ptr, declarations.ptr, seedPtr].forEach(
      (ptr) => core.unidpp_free(ptr, 0),
    );
    const note = takeNote(core);
    if (rc === 0) {
      return json(200, {
        relay: JSON.parse(note),
        evidence_hex: (v.evidence_hex ?? "").trim(),
      });
    }
    if (rc === -4) {
      return json(422, { error: note, refused: true });
    }
    return badRequest(note || `the relay failed (${rc})`);
  })();
};
