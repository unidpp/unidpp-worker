// The identity module on the estate (REARCH R12 S6): actors, scoped
// credentials, rotation and revocation, the scope table, whoami —
// the journal in DO storage with the same append-replay semantics.
// Enforcement is open-until-configured: an unconfigured deployment
// serves open, exactly as the native module does; the enforcement
// gate rides the estate router (this file's `gate`).

import { JournalOp, journalFor, Journal } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";

export interface Credential {
  id: string;
  actor: string;
  scopes: string[];
  secret_digest: string;
  status: "active" | "revoked";
  created_at: string;
  superseded_by?: string;
}

export interface Actor {
  id: string;
  org: string;
  name: string;
  scopes: string[];
  created_at: string;
}

const sha256Hex = (core: import("./wasm").CoreExports, data: Uint8Array): string => {
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  let value = "";
  for (const byte of out) value += byte.toString(16).padStart(2, "0");
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return value;
};

const isoNow = (): string => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const slug = (): string => {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const json = (status: number, body: unknown, asOf?: string): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...(asOf ? { "x-as-of": asOf } : {}),
    },
  });

const unauthorized = (): Response =>
  json(401, { error: "no credential presented" });

const forbidden = (scope: string): Response =>
  json(403, { error: "the credential lacks the scope", missing_scope: scope });

// The estate's scope table (the served-and-pinned truth; every
// module's read/write/admin scopes plus identity's own).
export const SCOPE_TABLE: Record<string, string[]> = {
  registry: ["read", "write", "admin"],
  trust: ["read", "write", "admin"],
  log: ["read", "append", "admin"],
  issuer: ["read", "write", "admin"],
  views: ["read", "write", "admin"],
  render: ["read", "write", "admin"],
  archive: ["read", "write", "admin"],
  relay: [],
  console: ["read", "write", "admin"],
  identity: ["read", "write", "admin"],
};

export function gate(
  pathname: string,
  request: Request,
  scopes: string[] | null,
): Response | null {
  const module = pathname.split("/")[1] ?? "";
  if (!(module in SCOPE_TABLE) || SCOPE_TABLE[module].length === 0) {
    // The deployment's own surface, the relay (authentication-free by
    // contract), the console (its own sessions), the identity surface
    // (self-enforcing).
    return null;
  }
  if (request.method === "GET") {
    // Reads ride the module's read scope.
    if (scopes === null) return unauthorized();
    if (!scopes.includes(`${module}:read`)) return forbidden(`${module}:read`);
    return null;
  }
  // Mutations ride the module's write scope (admin paths the admin
  // scope).
  const wantsAdmin = /(^|\/)admin(\/|$)/.test(pathname);
  const wanted = `${module}:${wantsAdmin ? "admin" : "write"}`;
  if (scopes === null) return unauthorized();
  if (!scopes.includes(wanted) && !scopes.includes(`${module}:admin`)) {
    return forbidden(wanted);
  }
  return null;
}

export class IdentityDO {
  private actors = new Map<string, Actor>();
  private credentials = new Map<string, Credential>();
  private journal: Journal;
  private core: CoreExports;
  private loaded = false;

  constructor(stateOrStorage: unknown, private readonly env: Record<string, string | undefined>) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
  }

  private get enforcing(): boolean {
    return Boolean(this.env.UNIDPP_SERVER_OPERATOR_TOKEN) || this.actors.size > 0;
  }

  private resolveBearer(request: Request): { scopes: string[]; actor: string } | null {
    const presented = request.headers.get("authorization");
    if (!presented?.startsWith("Bearer ")) return null;
    const token = presented.slice(7);
    const operator = this.env.UNIDPP_SERVER_OPERATOR_TOKEN;
    if (operator && token === operator) {
      return { scopes: ["*"], actor: "operator" };
    }
    const digest = sha256Hex(this.core, new TextEncoder().encode(token));
    for (const credential of this.credentials.values()) {
      if (credential.status === "active" && credential.secret_digest === digest) {
        return { scopes: credential.scopes, actor: credential.actor };
      }
    }
    return null;
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      for (const op of await this.journal.all()) this.apply(op);
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    const resolved = this.resolveBearer(request);
    const asOf = isoNow();
    const tenant = request.headers.get("x-unidpp-tenant") ?? this.env.UNIDPP_SERVER_TENANT ?? null;

    if (path === "/healthz") return json(200, { status: "ok" });
    if (path === "/keyring") {
      return json(200, {
        mode: this.enforcing ? "enforcing" : "open",
        note:
          "open = an unconfigured deployment; enrollment or an operator token closes it",
        operator_token: Boolean(this.env.UNIDPP_SERVER_OPERATOR_TOKEN),
        tenant,
      });
    }
    if (path === "/scopes") {
      const modules = Object.entries(SCOPE_TABLE).map(([name, levels]) => ({
        module: name,
        levels,
        scopes: levels.map((level) => `${name}:${level}`),
      }));
      return json(200, { modules, as_of: asOf });
    }
    if (path === "/whoami") {
      if (!resolved) return unauthorized();
      const actor = resolved.actor === "operator"
        ? { org: "operator", name: "the operator bypass", scopes: ["*"] }
        : this.actors.get(resolved.actor);
      return json(200, {
        actor: resolved.actor,
        org: actor?.org ?? null,
        name: actor?.name ?? null,
        scopes: resolved.scopes,
        tenant,
        as_of: asOf,
      }, asOf);
    }
    if (path === "/actors" && request.method === "POST") return this.enroll(request, resolved);
    if (path === "/actors" && request.method === "GET") {
      if (!resolved) return unauthorized();
      if (!resolved.scopes.includes("*") && !resolved.scopes.includes("identity:admin")) {
        return forbidden("identity:admin");
      }
      return json(200, { actors: [...this.actors.values()] });
    }
    const issue = path.match(/^\/actors\/([^/]+)\/credentials$/);
    if (issue && request.method === "POST") {
      if (!resolved) return unauthorized();
      if (!resolved.scopes.includes("*") && !resolved.scopes.includes("identity:admin")) {
        return forbidden("identity:admin");
      }
      return this.issueCredential(request, decodeURIComponent(issue[1]));
    }
    if (path === "/credentials" && request.method === "GET") {
      if (!resolved) return unauthorized();
      const mine = [...this.credentials.values()].filter(
        (c) => resolved.scopes.includes("*") || c.actor === resolved.actor,
      );
      return json(200, { credentials: mine.map(({ secret_digest: _digest, ...rest }) => rest) });
    }
    const rotate = path.match(/^\/credentials\/([^/]+)\/rotate$/);
    if (rotate && request.method === "POST") {
      return this.rotate(request, decodeURIComponent(rotate[1]), resolved);
    }
    const revoke = path.match(/^\/credentials\/([^/]+)\/revoke$/);
    if (revoke && request.method === "POST") {
      return this.revoke(request, decodeURIComponent(revoke[1]), resolved);
    }
    return json(404, { error: "no such path" });
  }

  private async enroll(request: Request, resolved: { scopes: string[]; actor: string } | null): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return json(400, { error: "invalid JSON body" });
    }
    const org = (v.org as string)?.trim();
    const name = (v.name as string)?.trim();
    const scopes = Array.isArray(v.scopes) ? (v.scopes as string[]) : [];
    if (!org || !name) return json(400, { error: "`org` and `name` are required" });
    // Bootstrap: an unconfigured deployment enrolls its first actor
    // without a credential; afterwards `identity:admin` governs.
    if (this.enforcing) {
      if (!resolved) return unauthorized();
      if (!resolved.scopes.includes("*") && !resolved.scopes.includes("identity:admin")) {
        return forbidden("identity:admin");
      }
    }
    const actor: Actor = {
      id: slug(),
      org,
      name,
      scopes,
      created_at: isoNow(),
    };
    const secret = `cred-${slug()}.${slug()}`;
    const credential: Credential = {
      id: slug(),
      actor: actor.id,
      scopes,
      secret_digest: sha256Hex(this.core, new TextEncoder().encode(secret)),
      status: "active",
      created_at: isoNow(),
    };
    await this.journal.append({
      op: "enroll",
      actor,
      credential: { ...credential, secret_digest: credential.secret_digest },
    });
    this.apply({ op: "enroll", actor, credential });
    return json(201, {
      actor: actor.id,
      org,
      name,
      scopes,
      credential: credential.id,
      bearer: secret,
      note: "the bearer is stated once; the store keeps only its digest",
    }, isoNow());
  }

  private async issueCredential(request: Request, actorId: string): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return json(400, { error: "invalid JSON body" });
    }
    const actor = this.actors.get(actorId);
    if (!actor) return json(404, { error: `no actor \`${actorId}\`` });
    const secret = `cred-${slug()}.${slug()}`;
    const credential: Credential = {
      id: slug(),
      actor: actorId,
      scopes: Array.isArray(v.scopes) ? (v.scopes as string[]) : actor.scopes,
      secret_digest: sha256Hex(this.core, new TextEncoder().encode(secret)),
      status: "active",
      created_at: isoNow(),
    };
    await this.journal.append({ op: "issue", credential });
    this.apply({ op: "issue", credential });
    return json(201, {
      actor: actorId,
      credential: credential.id,
      scopes: credential.scopes,
      bearer: secret,
      note: "the bearer is stated once; the store keeps only its digest",
    }, isoNow());
  }

  private async rotate(request: Request, credentialId: string, resolved: { scopes: string[]; actor: string } | null): Promise<Response> {
    if (!resolved) return unauthorized();
    const credential = this.credentials.get(credentialId);
    if (!credential) return json(404, { error: `no credential \`${credentialId}\`` });
    const own = credential.actor === resolved.actor;
    if (!own && !resolved.scopes.includes("*") && !resolved.scopes.includes("identity:admin")) {
      return forbidden("identity:admin");
    }
    let v: Record<string, unknown> = {};
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return json(400, { error: "invalid JSON body" });
    }
    const reason = (v.reason as string)?.trim() || "rotated";
    const secret = `cred-${slug()}.${slug()}`;
    const successor: Credential = {
      id: slug(),
      actor: credential.actor,
      scopes: credential.scopes,
      secret_digest: sha256Hex(this.core, new TextEncoder().encode(secret)),
      status: "active",
      created_at: isoNow(),
    };
    await this.journal.append({
      op: "rotate",
      credential_id: credentialId,
      successor,
      reason,
    });
    credential.status = "revoked";
    credential.superseded_by = successor.id;
    this.credentials.set(successor.id, successor);
    return json(201, {
      credential: successor.id,
      bearer: secret,
      superseded: credentialId,
      reason,
      note: "the old link revokes; the bearer is stated once",
    }, isoNow());
  }

  private async revoke(request: Request, credentialId: string, resolved: { scopes: string[]; actor: string } | null): Promise<Response> {
    if (!resolved) return unauthorized();
    const credential = this.credentials.get(credentialId);
    if (!credential) return json(404, { error: `no credential \`${credentialId}\`` });
    const own = credential.actor === resolved.actor;
    if (!own && !resolved.scopes.includes("*") && !resolved.scopes.includes("identity:admin")) {
      return forbidden("identity:admin");
    }
    let v: Record<string, unknown> = {};
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return json(400, { error: "invalid JSON body" });
    }
    const reason = (v.reason as string)?.trim() || "revoked";
    await this.journal.append({ op: "revoke", credential_id: credentialId, reason });
    credential.status = "revoked";
    return json(200, { credential: credentialId, status: "revoked", reason }, isoNow());
  }

  private apply(op: JournalOp): void {
    if (op.op === "enroll") {
      const actor = op.actor as Actor;
      const credential = op.credential as Credential;
      this.actors.set(actor.id, actor);
      this.credentials.set(credential.id, credential);
    } else if (op.op === "issue") {
      const credential = op.credential as Credential;
      this.credentials.set(credential.id, credential);
    } else if (op.op === "rotate") {
      const successor = op.successor as Credential;
      this.credentials.set(successor.id, successor);
      const old = this.credentials.get(op.credential_id as string);
      if (old) {
        old.status = "revoked";
        (old as Credential & { superseded_by?: string }).superseded_by = successor.id;
      }
    } else if (op.op === "revoke") {
      const old = this.credentials.get(op.credential_id as string);
      if (old) old.status = "revoked";
    }
  }
}
