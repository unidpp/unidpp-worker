// The Worker entry (REARCH R12): workerd accepts one handler export
// here; the estate itself lives in src/estate.ts and the wasm core
// mounts on the first request.

import { handle, useCore } from "./estate";
import { RegistryDO } from "./registry-do";
import { LogDO } from "./log-do";
import { TrustDO } from "./trust-do";
import { IssuerDO } from "./issuer-do";
import { ArchiveDO } from "./archive-do";
import { IdentityDO } from "./identity-do";
import { S13DO } from "./federation-do";
import { mountWorkerCore, useWorkerCore } from "./mount";
import { CoreExports } from "./wasm";

export { RegistryDO, LogDO, TrustDO, IssuerDO, ArchiveDO, IdentityDO, S13DO };

export default {
  async fetch(request: Request, env: unknown, _ctx: unknown): Promise<Response> {
    mountWorkerCore((instance: CoreExports) => {
      useCore(instance);
      useWorkerCore(instance);
    });
    return handle(request, env as Parameters<typeof handle>[1]);
  },
};
