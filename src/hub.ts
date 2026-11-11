// The translation hub on the estate (REARCH R12 S5): a stateless
// signed relay between willing pairs divided by protocols. The relay
// core and the declaration issuance are the signatif crate's own —
// willingness both ways (a scheme that declines is never brokered
// around; the absent declaration is stated), the canonical payload,
// the HUB-RELAY signature through the wasm boundary. The hub holds
// nothing: after the relay the state is gone.

import { workerCore } from "./mount";

const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

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

export const relay = (request: Request): Promise<Response> => {
  const core = workerCore();
  return (async () => {
    let v: RelayRequest;
    try {
      v = (await request.json()) as RelayRequest;
    } catch {
      return badRequest("invalid JSON body");
    }
    if (!/^[0-9a-fA-F]*$/.test(v.evidence_hex ?? "")) {
      return badRequest("`evidence_hex` must be hex");
    }
    const evidence = unhex((v.evidence_hex ?? "").trim());
    const encoder = new TextEncoder();
    const put = (text: string): { ptr: number; len: number } => {
      const bytes = encoder.encode(text);
      const ptr = core.unidpp_alloc(bytes.length);
      new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
      return { ptr, len: bytes.length };
    };
    const hubId = put(v.hub_id ?? "unidpp-hub");
    const from = put(v.from ?? "");
    const to = put(v.to ?? "");
    const dataClass = put(v.data_class ?? "");
    const declarations = put(JSON.stringify(v.declarations ?? { declarations: [] }));
    const evidenceBuf = put("");
    // The evidence bytes land in a buffer the core reads in place.
    new Uint8Array(core.memory.buffer, evidenceBuf.ptr, evidence.length).set(evidence);
    const evidencePart = { ptr: evidenceBuf.ptr, len: evidence.length };
    void evidenceBuf;
    const seed = unhex(sha256Label(core, "UNIDPP-HUB/OPERATOR-SEED"));
    const seedPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
    const rc = core.unidpp_hub_relay(
      hubId.ptr,
      hubId.len,
      evidencePart.ptr,
      evidence.length,
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
