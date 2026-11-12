// The console surface on the estate (REARCH R12 S5-serve): the
// operator console's HTML pages computed from the estate's own state
// — the modules table, the issuer's passports, the registry's items,
// the trust keyring, the tenant map, the archive's snapshots and the
// environment contract. Every interpolated value escapes (the
// console renders operator-supplied data); the session gate holds
// where UNIDPP_CONSOLE_ADMIN_TOKEN is configured, and an unconfigured
// deployment serves open (the native console's own doctrine).

import { workerCore } from "./mount";

export interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

export interface ConsoleEnv {
  ISSUER?: DoNamespace;
  UNIDPP_DESIGNER_SIGN_SEED?: string;
  REGISTRY?: DoNamespace;
  TRUST?: DoNamespace;
  ARCHIVE?: DoNamespace;
  UNIDPP_CONSOLE_ADMIN_TOKEN?: string;
  TENANT_HOSTS?: string;
}

export const CONSOLE_VERSION = "0.1.0";

const esc = (value: unknown): string =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const PAGES: ReadonlyArray<readonly [string, string]> = [
  ["/", "dashboard"],
  ["/designer", "designer"],
  ["/mappings", "mappings"],
  ["/passports", "passports"],
  ["/profiles", "profiles"],
  ["/registry", "registry"],
  ["/trust", "trust"],
  ["/tenants", "tenants"],
  ["/config", "config"],
  ["/archival", "archival"],
  ["/backups", "backups"],
  ["/egress", "egress"],
  ["/feedback", "feedback"],
  ["/coverage", "coverage"],
  ["/declarations", "declarations"],
  ["/carrier", "carrier"],
];

const html = (title: string, active: string, body: string): string => {
  const nav = PAGES.map(
    ([href, label]) =>
      `<a href="/console${href}"${label === active ? ` class="active"` : ""}>${esc(label)}</a>`,
  ).join("");
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${esc(title)} — UniDPP console</title>
<style>
body{font-family:sans-serif;margin:0;color:#17202a}
nav{background:#17202a;padding:0.5rem 1rem}
nav a{color:#d5dbdb;margin-right:0.75rem;text-decoration:none}
nav a.active{color:#ffffff;font-weight:bold}
main{padding:1rem 1.5rem;max-width:60rem}
h1{font-size:1.3rem} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #d5dbdb;padding:0.35rem 0.6rem;text-align:left;font-size:0.9rem}
.badge{padding:0.1rem 0.5rem;border-radius:0.6rem;font-size:0.8rem}
.badge.ok{background:#d4efdf;color:#1e8449}.badge.warn{background:#fdebd0;color:#b9770e}
form.inline{display:inline} input,button{font:inherit}
</style></head>
<body><nav>${nav}</nav><main>
<h1>${esc(title)}</h1>
${body}
</main></body></html>`;
};

const table = (headers: string[], rows: string[][]): string =>
  `<table><thead><tr>${headers
    .map((h) => `<th>${esc(h)}</th>`)
    .join("")}</tr></thead><tbody>${rows
    .map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`)
    .join("")}</tbody></table>`;

const badge = (text: string, kind: "ok" | "warn" = "ok"): string =>
  `<span class="badge ${kind}">${esc(text)}</span>`;

const htmlResponse = (body: string, status = 200): Response =>
  new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

// The session seal: the admin token's digest through the boundary's
// sha256 — the cookie carries the digest, never the token.
function sessionCookie(core: ReturnType<typeof workerCore>, token: string): string {
  const bytes = new TextEncoder().encode(`console-session:${token}`);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  const outPtr = core.unidpp_alloc(32);
  core.unidpp_sha256(ptr, bytes.length, outPtr);
  let digest = "";
  for (const byte of new Uint8Array(core.memory.buffer, outPtr, 32)) {
    digest += byte.toString(16).padStart(2, "0");
  }
  core.unidpp_free(ptr, bytes.length);
  core.unidpp_free(outPtr, 32);
  return digest;
}

// The gate: null serves, "refused" redirects an unauthenticated
// browser to /console/login (an unconfigured token serves open).
function gate(request: Request, env: ConsoleEnv): "refused" | null {
  const token = env.UNIDPP_CONSOLE_ADMIN_TOKEN;
  if (!token) return null;
  const pathname = new URL(request.url).pathname;
  if (pathname === "/console/login") return null;
  if (pathname === "/console/logout") return null;
  const cookie = request.headers.get("cookie") ?? "";
  const expected = sessionCookie(workerCore(), token);
  const present = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("unidpp-console="));
  if (present && present.slice("unidpp-console=".length) === expected) return null;
  return "refused";
}

async function doJson(
  ns: DoNamespace | undefined,
  path: string,
): Promise<Record<string, unknown> | null> {
  if (!ns) return null;
  const stub = ns.get(ns.idFromName("estate"));
  const response = await stub.fetch(new Request(`https://do.internal${path}`));
  if (response.status !== 200) return null;
  return (await response.json()) as Record<string, unknown>;
}

// The estate's module table — the dashboard's cards (the same table
// the union contract serves).
const MODULE_CARDS: ReadonlyArray<readonly [string, string]> = [
  ["registry", "registry.unidpp.org"],
  ["trust", "trust.unidpp.org"],
  ["log", "log.unidpp.org"],
  ["issuer", "app.unidpp.org"],
  ["views", "app.unidpp.org"],
  ["render", "app.unidpp.org"],
  ["archive", "app.unidpp.org"],
  ["relay", "hub.unidpp.org"],
  ["console", "console.unidpp.org"],
  ["identity", "app.unidpp.org"],
];

async function page(pathname: string, request: Request, env: ConsoleEnv): Promise<Response> {
  switch (pathname) {
    case "/":
    case "": {
      const rows = MODULE_CARDS.map(([name, host]) => [
        esc(name),
        esc(`/${name}`),
        badge("healthy"),
        esc(host),
      ]);
      return htmlResponse(html("The deployment", "dashboard", table(["module", "prefix", "readiness", "public hostname"], rows)));
    }
    case "/designer": {
      const { designer } = await import("./designer");
      return designer(request, {
        REGISTRY: env.REGISTRY,
        UNIDPP_DESIGNER_SIGN_SEED: env.UNIDPP_DESIGNER_SIGN_SEED,
      });
    }
    case "/mappings": {
      const { workbench } = await import("./mappings");
      return workbench(request, { REGISTRY: env.REGISTRY });
    }
    case "/passports": {
      const listed = await doJson(env.ISSUER, "/passports");
      const passports =
        (listed?.passports as { passport_id: string; subject?: string; audit_seq: number }[]) ?? [];
      const rows = passports.map((p) => [
        esc(p.passport_id),
        esc(p.subject ?? ""),
        esc(p.audit_seq),
        badge("issued"),
      ]);
      const form = `<p>The verification form rides the trust surface:</p>
<form method="get" action="/trust/verify"><input name="passport" placeholder="passport id"><button type="submit">verify</button></form>`;
      return htmlResponse(html("Passports", "passports", form + table(["passport id", "subject", "audit seq", "state"], rows)));
    }
    case "/profiles":
    case "/registry": {
      const listed = await doJson(env.REGISTRY, "/items");
      const items =
        (listed?.items as {
          identifier?: string;
          item_class?: string;
          version?: { version?: string } | string;
        }[]) ?? [];
      const rows = items.map((i) => [
        esc(i.identifier ?? ""),
        esc(i.item_class ?? ""),
        esc(typeof i.version === "string" ? i.version : (i.version?.version ?? "")),
      ]);
      return htmlResponse(html("The register", pathname === "/profiles" ? "profiles" : "registry", table(["item", "class", "version"], rows)));
    }
    case "/trust": {
      const keyring = await doJson(env.TRUST, "/keyring");
      const keys = (keyring?.keys as { key_id?: string; status?: string }[]) ?? [];
      const rows = keys.map((k) => [esc(k.key_id ?? ""), esc(k.status ?? ""), badge(k.status === "trusted" ? "trusted" : "stated")]);
      return htmlResponse(html("Trust", "trust", table(["key id", "status", "posture"], rows)));
    }
    case "/tenants": {
      let rows: string[][] = [];
      try {
        const map = JSON.parse(env.TENANT_HOSTS ?? "{}") as Record<string, string>;
        rows = Object.entries(map).map(([host, tenant]) => [esc(host), esc(tenant), badge("mapped")]);
      } catch {
        rows = [];
      }
      const note = `<p>Tenants are folders under one process (REARCH R6): the Host header names the folder.</p>`;
      return htmlResponse(html("Tenants", "tenants", note + table(["hostname", "tenant", "dispatch"], rows)));
    }
    case "/config": {
      const contract = [
        "UNIDPP_SERVER_OPERATOR_TOKEN",
        "UNIDPP_SERVER_TENANT",
        "UNIDPP_SERVER_LOG_SEED",
        "UNIDPP_CONSOLE_ADMIN_TOKEN",
        "TENANT_HOSTS",
      ];
      const rows = contract.map((key) => [
        `<code>${esc(key)}</code>`,
        esc("${" + key + "}"),
      ]);
      return htmlResponse(html("The manifest as data", "config", table(["environment key", "reference"], rows)));
    }
    case "/archival":
    case "/backups": {
      const listed = await doJson(env.ARCHIVE, "/snapshots");
      const snapshots = (listed?.snapshots as { id?: string; tree_size?: number; created_at?: string }[]) ?? [];
      const rows = snapshots.map((s) => [
        esc(s.id ?? ""),
        esc(s.tree_size ?? ""),
        esc(s.created_at ?? ""),
        badge("anchored"),
      ]);
      const drill =
        pathname === "/backups"
          ? `<p>The restore drill notarizes a stated state through the archive:</p>
<form method="post" action="/console/backups/drill">
<input name="passport_id" placeholder="passport id">
<input name="state_hash" placeholder="state hash (64-char hex)">
<input name="log_head" placeholder="log head (64-char hex)">
<button type="submit">run restore drill</button>
</form>`
          : "";
      return htmlResponse(html("Archival", "backups", drill + table(["snapshot", "tree size", "created", "anchor"], rows)));
    }
    case "/egress": {
      const rows = [
        [esc("ARCHIVE_BUCKET (R2)"), esc("snapshot writes"), badge("declared")],
        [esc("Durable Objects"), esc("journal storage"), badge("declared")],
        [esc("public hostnames"), esc("Cloudflare tunnel"), badge("declared")],
      ];
      const note = `<p>The deployment's outbound surfaces, sealed rows and real rows alike.</p>`;
      return htmlResponse(html("Egress", "egress", note + table(["binding", "direction", "posture"], rows)));
    }
    case "/feedback": {
      const note = `<p>The consumer-reports channel rides the relay surface (authentication-free by contract); the estate keeps no report store on the edge.</p>`;
      return htmlResponse(html("Feedback", "feedback", note));
    }
    case "/coverage": {
      const form = `<p>The coverage report computes per passport and profile through the views surface:</p>
<form method="get" action="/views/view"><input name="passport" placeholder="passport id"><input name="profile" placeholder="profile id"><button type="submit">view</button></form>`;
      return htmlResponse(html("Coverage", "coverage", form));
    }
    case "/declarations": {
      const note = `<p>The signed declarations ride the issuer surface's event log; the relay mints the cross-organization declarations.</p>`;
      return htmlResponse(html("Declarations", "declarations", note));
    }
    case "/carrier": {
      const note = `<p>The carrier journey (generation and translation) computes through the render surface's protocol renderings.</p>`;
      return htmlResponse(html("Carrier", "carrier", note));
    }
    case "/branding": {
      const body = `<table><thead><tr><th>aspect</th><th>value</th></tr></thead><tbody>
<tr><td>service</td><td>unidpp</td></tr>
<tr><td>locale</td><td>en</td></tr>
<tr><td>console version</td><td>${esc(CONSOLE_VERSION)}</td></tr>
</tbody></table>`;
      return htmlResponse(html("Branding", "branding", body));
    }
    case "/login": {
      if (request.method === "POST") {
        const token = env.UNIDPP_CONSOLE_ADMIN_TOKEN;
        let submitted = "";
        try {
          const body = (await request.formData()) as FormData;
          submitted = String(body.get("token") ?? "");
        } catch {
          submitted = "";
        }
        if (token && submitted === token) {
          return new Response("", {
            status: 303,
            headers: {
              "set-cookie": `unidpp-console=${sessionCookie(workerCore(), token)}; Path=/; HttpOnly; SameSite=Lax`,
              location: "/console/",
            },
          });
        }
        return htmlResponse(
          html("Login", "dashboard",
            `<p>The token was refused.</p>
<form method="post"><input type="password" name="token"><button type="submit">sign in</button></form>`),
          200,
        );
      }
      const gateNote = env.UNIDPP_CONSOLE_ADMIN_TOKEN
        ? "The admin token gates this console."
        : "No admin token is configured: this console serves open.";
      return htmlResponse(
        html("Login", "dashboard",
          `<p>${esc(gateNote)}</p>
<form method="post"><input type="password" name="token"><button type="submit">sign in</button></form>`),
      );
    }
    case "/logout": {
      return new Response("", {
        status: 303,
        headers: {
          "set-cookie": "unidpp-console=; Path=/; Max-Age=0",
          location: "/console/login",
        },
      });
    }
    default:
      return jsonResponse({ error: "no such console path" }, 404);
  }
}

export async function consoleSurface(
  pathname: string,
  request: Request,
  env: ConsoleEnv,
): Promise<Response> {
  // /.well-known and /healthz answer ungated (the orchestrator's probes).
  if (pathname === "/healthz") return jsonResponse({ status: "ok" });
  if (pathname === "/.well-known/unidpp-service") {
    return jsonResponse({ service: "unidpp", version: CONSOLE_VERSION, runtime: "cloudflare-workers" });
  }
  if (gate(request, env) === "refused") {
    return new Response("", { status: 303, headers: { location: "/console/login" } });
  }
  if (pathname === "/backups/drill" && request.method === "POST") {
    if (!env.ARCHIVE) return jsonResponse({ error: "the archive Durable Object is not bound" }, 503);
    let form: FormData;
    try {
      form = (await request.formData()) as FormData;
    } catch {
      return jsonResponse({ error: "the drill posts a form" }, 400);
    }
    const payload = {
      passport_id: String(form.get("passport_id") ?? ""),
      state_hash: String(form.get("state_hash") ?? ""),
      log_head: String(form.get("log_head") ?? ""),
      submitter: "console-backup-drill",
    };
    const stub = env.ARCHIVE.get(env.ARCHIVE.idFromName("estate"));
    const drilled = await stub.fetch(
      new Request("https://do.internal/snapshots", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    );
    const body = (await drilled.json()) as Record<string, unknown>;
    return jsonResponse(body, drilled.status);
  }
  return page(pathname, request, env);
}
