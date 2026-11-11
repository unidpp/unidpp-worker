// The wasm core, resolved once per isolate (REARCH R12): workerd
// hands the CompiledWasm import as a WebAssembly module — pure, no
// imports — so each isolate (the entry's and every Durable Object's)
// instantiates its own copy; vitest mounts bytes. Idempotent: the
// first caller pays the instantiation.

import wasmModule from "../src/core_bg.wasm";
import { CoreExports } from "./wasm";

let mounted: CoreExports | null = null;

function resolve(): CoreExports {
  if (mounted) return mounted;
  const wasm: unknown = wasmModule;
  const asInstance = wasm as { exports?: CoreExports };
  if (asInstance.exports && Object.keys(asInstance.exports).length > 0) {
    mounted = asInstance.exports;
    return mounted;
  }
  try {
    // The module probe: workerd's CompiledWasm import is a module.
    WebAssembly.Module.exports(wasm as WebAssembly.Module);
    const instance = new WebAssembly.Instance(
      wasm as unknown as WebAssembly.Module,
      {} as WebAssembly.Imports,
    );
    mounted = instance.exports as unknown as CoreExports;
    return mounted;
  } catch {
    throw new Error("the wasm core is not mounted and cannot self-instantiate");
  }
}

export function useWorkerCore(instance: CoreExports): void {
  mounted = instance;
}

export function workerCore(): CoreExports {
  return resolve();
}

export function mountWorkerCore(use: (instance: CoreExports) => void): void {
  use(resolve());
}
