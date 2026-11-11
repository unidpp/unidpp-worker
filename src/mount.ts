// The wasm core, mounted once for the whole Worker (REARCH R12): the
// entry mounts the CompiledWasm instance before any handler runs; the
// Durable Objects and every consumer read it through here.

import wasmInstance from "../src/core_bg.wasm";
import { CoreExports } from "./wasm";

interface WebAssemblyModule {
  exports?: unknown;
}

function isModuleLike(value: unknown): boolean {
  try {
    WebAssembly.Module.exports(value as WebAssembly.Module);
    return true;
  } catch {
    return false;
  }
}

let mounted: CoreExports | null = null;

export function useWorkerCore(instance: CoreExports): void {
  mounted = instance;
}

// workerd hands the CompiledWasm import over as the instantiated pure
// module (no imports, no glue); the entry resolves it once.
export function mountWorkerCore(use: (instance: CoreExports) => void): void {
  if (mounted) {
    use(mounted);
    return;
  }
  const wasm: unknown = wasmInstance;
  const asInstance = wasm as { exports?: CoreExports };
  if (asInstance.exports && Object.keys(asInstance.exports).length > 0) {
    mounted = asInstance.exports;
    use(mounted);
    return;
  }
  // workerd hands the CompiledWasm import over as a WebAssembly
  // MODULE: the module is pure (no imports), so instantiating it here
  // is the whole ceremony.
  const asModule = wasm as WebAssemblyModule;
  if (typeof asModule.exports === "function" || (wasm as { constructor?: { name?: string } }).constructor?.name === "WebAssemblyModule" || isModuleLike(wasm)) {
    const instance = new WebAssembly.Instance(wasm as unknown as WebAssembly.Module, []);
    mounted = instance.exports as unknown as CoreExports;
    use(mounted);
    return;
  }
  use(wasm as CoreExports);
}

export function workerCore(): CoreExports {
  if (mounted) return mounted;
  const wasm: unknown = wasmInstance;
  const candidate = (wasm as { exports?: CoreExports }).exports;
  if (candidate) {
    mounted = candidate;
    return mounted;
  }
  throw new Error("the wasm core is not mounted");
}
