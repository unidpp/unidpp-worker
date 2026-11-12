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

interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

interface Env {
  REGISTRY?: DoNamespace;
  LOG?: DoNamespace;
  TRUST?: DoNamespace;
  ISSUER?: DoNamespace;
  ARCHIVE?: DoNamespace;
  IDENTITY?: DoNamespace;
  UNIDPP_SERVER_OPERATOR_TOKEN?: string;
  /** Host→tenant dispatch (REARCH R6 on Workers): a JSON map
   * {"dpp.acme.example.org": "acme"} — a request whose Host names a
   * tenant is served from that tenant's own DO namespaces (each DO
   * id suffixed), its own journals, its own identity. */
  TENANT_HOSTS?: string;
  UNIDPP_CONSOLE_ADMIN_TOKEN?: string;
  UNIDPP_DESIGNER_SIGN_SEED?: string;
  ARCHIVE_BUCKET?: { put(key: string, value: string): Promise<unknown>; get(key: string): Promise<{ text(): Promise<string> } | null> };
}

export async function handle(request: Request, env?: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  // The tenant dispatch (REARCH R6 on Workers): the request's Host
  // names a tenant when TENANT_HOSTS declares it; every DO forward
  // then rides that tenant's own namespaces.
  let tenant: string | null = null;
  if (env?.TENANT_HOSTS) {
    try {
      const hosts = JSON.parse(env.TENANT_HOSTS) as Record<string, string>;
      const host = request.headers.get("host")?.split(":")[0];
      if (host && hosts[host]) tenant = hosts[host];
    } catch {
      // a malformed map dispatches nobody
    }
  }
  const namespace = (ns: DoNamespace | undefined, name: string) =>
    ns ? ns.get(ns.idFromName(tenant ? `${name}@${tenant}` : name)) : null;
  // The registry rides its Durable Object (REARCH R12 S2): every
  // request under the prefix is served by the estate's one DO.
  const registryRest = pathname.startsWith("/registry/")
    ? pathname.slice("/registry".length)
    : null;
  // The DATA surface rides the Durable Object (REARCH R12 S2); the
  // contract and health answers stay the embedded goldens.
  const registryData = registryRest?.match(/^\/(items|applicability|admin|models|discovery|debug-journal)($|\/)/);
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
  // The transparency log and the trust surface ride their own
  // Durable Objects (REARCH R12 S3).
  const logRest = pathname.startsWith("/log/") ? pathname.slice("/log".length) : null;
  const logData = logRest?.match(/^\/(commitments|receipt|tree|admin)($|\/)/);
  if (logRest && logData) {
    if (!env?.LOG) {
      return new Response(
        JSON.stringify({ error: "the log Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const stub = namespace(env.LOG, "estate");
    const inner = new URL(request.url);
    inner.pathname = logRest;
    return stub!.fetch(new Request(inner.toString(), request));
  }
  // The relay is STATELESS: it answers in the estate module itself
  // (REARCH R12 S5 — the hub carries no storage and no journal).
  if (pathname === "/relay/relay") {
    const { relay } = await import("./hub");
    return relay(request);
  }
  const identityRest = pathname.startsWith("/identity/")
    ? pathname.slice("/identity".length)
    : null;
  const identityData = identityRest?.match(
    /^\/(actors|credentials|whoami|keyring|scopes)($|\/)/,
  );
  if (identityRest && identityData) {
    if (!env?.IDENTITY) {
      return new Response(
        JSON.stringify({ error: "the identity Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const stub = namespace(env.IDENTITY, "estate");
    const inner = new URL(request.url);
    inner.pathname = identityRest;
    if (tenant) {
      const headers = new Headers(request.headers);
      headers.set("x-unidpp-tenant", tenant);
      return stub!.fetch(
        new Request(inner.toString(), {
          method: request.method,
          headers,
          body: request.body,
        }),
      );
    }
    return stub!.fetch(new Request(inner.toString(), request));
  }
  // The views surface (REARCH R12 S5-serve): the lens view computed
  // through the wasm boundary, the sources the estate's own DOs.
  if (pathname === "/views/view") {
    const { view } = await import("./views");
    return view(request, {
      ISSUER: env?.ISSUER,
      REGISTRY: env?.REGISTRY,
    });
  }
  // The render surface (REARCH R12 S5-serve): the EN 18222 document
  // and the UNTP triad computed through the wasm boundary — the same
  // renderers the native gateway compiles.
  const renderRest = pathname.startsWith("/render/") ? pathname.slice("/render".length) : null;
  if (renderRest && /^\/(en18222|untp)\//.test(renderRest)) {
    const { render } = await import("./render");
    return render(renderRest, request, { ISSUER: env?.ISSUER });
  }
  // The console surface (REARCH R12 S5-serve): the operator pages
  // computed from the estate's own state, session-gated where an
  // admin token is configured.
  const consoleRest = pathname === "/console" ? "/" : pathname.startsWith("/console/") ? pathname.slice("/console".length) : null;
  // The pinned contract rides the module loop (the golden and the
  // health probe answer before the console's own pages).
  if (consoleRest !== null && consoleRest !== "/openapi.yaml" && consoleRest !== "/healthz") {
    const { consoleSurface } = await import("./console");
    return consoleSurface(consoleRest, request, {
      ISSUER: env?.ISSUER,
      REGISTRY: env?.REGISTRY,
      TRUST: env?.TRUST,
      ARCHIVE: env?.ARCHIVE,
      UNIDPP_CONSOLE_ADMIN_TOKEN: env?.UNIDPP_CONSOLE_ADMIN_TOKEN,
      UNIDPP_DESIGNER_SIGN_SEED: env?.UNIDPP_DESIGNER_SIGN_SEED,
      TENANT_HOSTS: env?.TENANT_HOSTS,
    });
  }
  const issuerRest = pathname.startsWith("/issuer/") ? pathname.slice("/issuer".length) : null;
  const issuerData = issuerRest?.match(/^\/(passports|admin|events)($|\/)/);
  if (issuerRest && issuerData) {
    if (!env?.ISSUER) {
      return new Response(
        JSON.stringify({ error: "the issuer Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const stub = namespace(env.ISSUER, "estate");
    const inner = new URL(request.url);
    inner.pathname = issuerRest;
    return stub!.fetch(new Request(inner.toString(), request));
  }
  const archiveRest = pathname.startsWith("/archive/") ? pathname.slice("/archive".length) : null;
  const archiveData = archiveRest?.match(/^\/(snapshots|admin)($|\/)/);
  if (archiveRest && archiveData) {
    if (!env?.ARCHIVE) {
      return new Response(
        JSON.stringify({ error: "the archive Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const stub = namespace(env.ARCHIVE, "estate");
    const inner = new URL(request.url);
    inner.pathname = archiveRest;
    return stub!.fetch(new Request(inner.toString(), request));
  }
  const trustRest = pathname.startsWith("/trust/") ? pathname.slice("/trust".length) : null;
  const trustData = trustRest?.match(/^\/(keyring|verify|graph|anchors)($|\/)/);
  if (trustRest && trustData) {
    if (!env?.TRUST) {
      return new Response(
        JSON.stringify({ error: "the trust Durable Object is not bound" }),
        { status: 503, headers: { "content-type": "application/json" } },
      );
    }
    const stub = namespace(env.TRUST, "estate");
    const inner = new URL(request.url);
    inner.pathname = trustRest;
    return stub!.fetch(new Request(inner.toString(), request));
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

