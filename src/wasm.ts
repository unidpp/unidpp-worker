// The wasm core's contract (REARCH R12): a pure module with no
// imports — unidpp_alloc, unidpp_sha256, unidpp_free — instantiable
// the same way in workerd (CompiledWasm import) and in tests (bytes).

export interface CoreExports {
  memory: WebAssembly.Memory;
  unidpp_alloc: (len: number) => number;
  unidpp_free: (ptr: number, len: number) => void;
  unidpp_sha256: (ptr: number, len: number, out: number) => void;
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
