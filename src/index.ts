// The Worker entry (REARCH R12): workerd accepts one handler export
// here; the estate itself lives in src/estate.ts and the wasm core
// mounts on the first request.

import wasmInstance from "../src/core_bg.wasm";
import { CoreExports } from "./wasm";
import { handle, useCore } from "./estate";

export default {
  async fetch(request: Request, _env: unknown, _ctx: unknown): Promise<Response> {
    const wasm: unknown = wasmInstance;
    const candidate = (wasm as { exports?: CoreExports }).exports;
    if (candidate) {
      useCore(candidate);
    } else {
      useCore(wasm as CoreExports);
    }
    return handle(request);
  },
};
