// UniDPP on Cloudflare Workers (REARCH R12): the union surface of
// the one deployment, native to the edge, in TypeScript with the
// Rust core riding as WASM. The ten module goldens and the union
// contract are embedded verbatim and served byte-identically behind
// their prefixes; the digest path of the estate's core is the wasm
// module the vector corpus pins.

import unionGolden from "../goldens/union-golden.yaml";
import registryGolden from "../goldens/unidpp-registry.yaml";
import trustGolden from "../goldens/unidpp-trust.yaml";
import logGolden from "../goldens/unidpp-log.yaml";
import issuerGolden from "../goldens/unidpp-issuer.yaml";
import projectorGolden from "../goldens/unidpp-projector.yaml";
import gatewayGolden from "../goldens/unidpp-gateway.yaml";
import archiveGolden from "../goldens/unidpp-archive.yaml";
import hubGolden from "../goldens/unidpp-hub.yaml";
import consoleGolden from "../goldens/unidpp-console.yaml";
import identityGolden from "../goldens/identity.yaml";
import { CoreExports, digestHex } from "./wasm";

export const VERSION = "0.1.0";

// (module name = URL prefix, source service, the golden document).
// The order is the union document's order — stable by construction.
export const MODULES: ReadonlyArray<readonly [string, string, string]> = [
  ["registry", "unidpp-registry", registryGolden],
  ["trust", "unidpp-trust", trustGolden],
  ["log", "unidpp-log", logGolden],
  ["issuer", "unidpp-issuer", issuerGolden],
  ["views", "unidpp-projector", projectorGolden],
  ["render", "unidpp-gateway", gatewayGolden],
  ["archive", "unidpp-archive", archiveGolden],
  ["relay", "unidpp-hub", hubGolden],
  ["console", "unidpp-console", consoleGolden],
  ["identity", "unidpp-server", identityGolden],
];

export function discoveryDocument(): Record<string, unknown> {
  const modules = MODULES.map(([name, source]) => ({
    name,
    service: source,
    prefix: `/${name}`,
    contract: `/${name}/openapi.yaml`,
    health: `/${name}/healthz`,
  }));
  return {
    service: "unidpp",
    version: VERSION,
    description:
      "UniDPP as one deployment: every module of the estate in one surface (on Cloudflare Workers, REARCH R12)",
    modules,
    contract: [
      "one service: every module shares one process, one port and one data root",
      "contracts unchanged: each module serves its golden document behind its prefix",
      "multi-user: operations carry actor scopes (the identity module)",
      "multi-tenant: tenants are folders under one process, not deployments",
    ],
  };
}

const yaml = (body: string): Response =>
  new Response(body, {
    headers: { "content-type": "application/yaml" },
  });

const json = (body: unknown): Response =>
  new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
  });

// The wasm core, mounted at startup: workerd provides the
// CompiledWasm import (an instantiated pure module) and tests provide
// their own instance of the same bytes.
let mounted: CoreExports | null = null;
export function useCore(instance: CoreExports): void {
  mounted = instance;
}

function core(): CoreExports {
  if (!mounted) {
    throw new Error("the wasm core is not mounted (call useCore)");
  }
  return mounted;
}

// The estate's digest path through the wasm core: the same bytes the
// native binaries produce (pinned by the vector corpus).
export function coreDigest(data: Uint8Array): string {
  return digestHex(core(), data);
}

interface Env {
  REGISTRY?: { idFromName(name: string): { toString(): string }; get(id: unknown): { fetch(request: Request): Promise<Response> } };
}

export async function handle(request: Request, env?: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  // The registry rides its Durable Object (REARCH R12 S2): every
  // request under the prefix is served by the estate's one DO.
  const registryRest = pathname.startsWith("/registry/")
    ? pathname.slice("/registry".length)
    : null;
  // The DATA surface rides the Durable Object (REARCH R12 S2); the
  // contract and health answers stay the embedded goldens.
  const registryData = registryRest?.match(/^\/(items|applicability|admin|models)($|\/)/);
  if (registryRest && registryData) {
    if (!env?.REGISTRY) {
      return new Response(
        JSON.stringify({ error: "the registry Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const id = env.REGISTRY.idFromName("estate");
    const stub = env.REGISTRY.get(id);
    const inner = new URL(request.url);
    inner.pathname = registryRest;
    return stub.fetch(new Request(inner.toString(), request));
  }
  switch (pathname) {
    case "/healthz":
      return json({ status: "ok" });
    case "/version":
      return json({
        service: "unidpp",
        version: VERSION,
        runtime: "cloudflare-workers",
      });
    case "/":
      return json(discoveryDocument());
    case "/openapi.yaml":
      return yaml(unionGolden);
    case "/openapi.json": {
      // js-yaml rides only where a client wants JSON; the YAML
      // document itself is the embedded golden, served verbatim.
      const { load } = await import("js-yaml");
      return json(load(unionGolden));
    }
    default: {
      for (const [name, _source, golden] of MODULES) {
        const prefix = `/${name}/`;
        if (pathname.startsWith(prefix)) {
          const rest = pathname.slice(prefix.length);
          if (rest === "healthz") return json({ status: "ok" });
          if (rest === "openapi.yaml") return yaml(golden);
          break;
        }
      }
      return new Response(JSON.stringify({ error: "no such path" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
  }
}

