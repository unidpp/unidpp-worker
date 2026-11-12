// The wasm core's contract (REARCH R12): a pure module with no
// imports — unidpp_alloc, unidpp_sha256, unidpp_free — instantiable
// the same way in workerd (CompiledWasm import) and in tests (bytes).

export interface CoreExports {
  memory: WebAssembly.Memory;
  unidpp_alloc: (len: number) => number;
  unidpp_free: (ptr: number, len: number) => void;
  unidpp_sha256: (ptr: number, len: number, out: number) => void;
  unidpp_head_public: (seed: number, out: number) => number;
  unidpp_head_key_id: (seed: number, out: number) => number;
  unidpp_sth_sign: (
    seed: number,
    logId: number,
    logIdLen: number,
    treeSize: bigint,
    secs: bigint,
    nanos: number,
    root: number,
    sigOut: number,
  ) => number;
  unidpp_mint_passport: (
    id: number,
    idLen: number,
    granularity: number,
    granularityLen: number,
    capability: number,
    capabilityLen: number,
    passportId: number,
    passportIdLen: number,
    validFromSecs: bigint,
    outLen: number,
    err: number,
  ) => number;
  unidpp_sign_raw: (
    seed: number,
    domain: number,
    domainLen: number,
    payload: number,
    payloadLen: number,
    sigOut: number,
  ) => number;
  unidpp_debug_note: () => number;
  unidpp_debug_parse_identity: (id: number, idLen: number) => number;
  unidpp_view_project: (
    passport: number,
    passportLen: number,
    lens: number,
    lensLen: number,
    atSecs: bigint,
    actor: number,
    actorLen: number,
  ) => number;
  unidpp_fixture_lens: (profile: number, profileLen: number) => number;
  unidpp_fixture_passport: () => number;
  unidpp_mapping_validate: (item: number, itemLen: number) => number;
  unidpp_mapping_compose: (
    first: number,
    firstLen: number,
    second: number,
    secondLen: number,
    cap: bigint,
  ) => number;
  unidpp_render: (
    protocol: number,
    protocolLen: number,
    passport: number,
    passportLen: number,
    profiles: number,
    profilesLen: number,
    representation: number,
    representationLen: number,
    freshness: number,
    freshnessLen: number,
    origin: number,
    originLen: number,
    nowSecs: bigint,
  ) => number;
  unidpp_hub_relay: (
    hubId: number,
    hubIdLen: number,
    evidence: number,
    evidenceLen: number,
    from: number,
    fromLen: number,
    to: number,
    toLen: number,
    dataClass: number,
    dataClassLen: number,
    seed: number,
    declarations: number,
    declarationsLen: number,
  ) => number;
  unidpp_declaration_issue: (
    seed: number,
    declarer: number,
    declarerLen: number,
    counterpart: number,
    counterpartLen: number,
    version: bigint,
    postures: number,
    posturesLen: number,
    validFrom: number,
    validFromLen: number,
    validTo: number,
    validToLen: number,
  ) => number;
  unidpp_note_take: (out: number) => number;
  unidpp_sth_verify: (
    publicKey: number,
    logId: number,
    logIdLen: number,
    treeSize: bigint,
    secs: bigint,
    nanos: number,
    root: number,
    signature: number,
  ) => number;
}

export function digestHex(core: CoreExports, data: Uint8Array): string {
  const ptr = core.unidpp_alloc(data.length);
  // The allocation may have grown the memory: read the buffer after.
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  let hex = "";
  for (const byte of out) hex += byte.toString(16).padStart(2, "0");
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return hex;
}
