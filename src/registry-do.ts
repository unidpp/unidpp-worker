// The registry on a Durable Object (REARCH R12 S2): item
// registration, version supersession, and point-in-time resolution
// with the journal in DO storage — the same append-replay semantics
// the native store keeps, the same wire shapes the registry golden
// describes. The intake chain rides later slices; the validations
// here are the ones the create/supersede handlers themselves carry
// (required fields, token shape, status rules, window order, the
// manifest version pin).

export interface ItemVersion {
  version: string;
  status: string;
  effective_from: string | null;
  effective_until: string | null;
  registered_at: string | null;
  superseded_by_version: string | null;
  notes: string | null;
}

export interface Item {
  identifier: string;
  register: string;
  item_class: string;
  title: string;
  submitting_organization?: string;
  versions: ItemVersion[];
  manifest?: Record<string, unknown>;
}

export interface JournalOp {
  op: string;
  [key: string]: unknown;
}

export const ITEM_CLASSES = [
  "data-element",
  "profile",
  "crypto-suite",
  "transform",
  "trust-anchor",
  "unit",
  "model",
  "cross-register-mapping",
];

// The plural mount names the subregisters answer under.
const CLASS_PLURALS: Record<string, string> = {
  "data-element": "data-elements",
  profile: "profiles",
  "crypto-suite": "crypto-suites",
  transform: "transforms",
  "trust-anchor": "trust-anchors",
  unit: "units",
  model: "models",
  "cross-register-mapping": "cross-register-mappings",
};

export const STATUSES = ["valid", "superseded", "retired"];

const tokenOk = (value: string): boolean =>
  value.length > 0 && value.length <= 256 && !value.includes("/") && !/\s/.test(value);

export function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const notFound = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 404,
    headers: { "content-type": "application/json" },
  });

const stamped = (status: number, body: unknown, asOf: string): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-as-of": asOf },
  });

// One version's own view (the Rust `ItemVersion::to_json`).
export function renderVersion(item: Item, candidate: ItemVersion): Record<string, unknown> {
  const view: Record<string, unknown> = {
    version: candidate.version,
    status: candidate.status,
  };
  if (candidate.effective_from) view.effective_from = candidate.effective_from;
  if (candidate.effective_until) view.effective_until = candidate.effective_until;
  if (candidate.registered_at) view.registered_at = candidate.registered_at;
  if (candidate.superseded_by_version)
    view.superseded_by_version = candidate.superseded_by_version;
  if (candidate.notes) view.notes = candidate.notes;
  // The successor's effective_from closes this window.
  if (candidate.superseded_by_version) {
    const successor = item.versions.find(
      (v) => v.version === candidate.superseded_by_version,
    );
    if (successor?.effective_from) view.window_end = successor.effective_from;
  }
  return view;
}

// The version in force at `at` (absent `at`: the current registered
// state — the latest registered version).
export function versionJson(
  item: Item,
  at: Date | null,
  _asOf: Date,
): Record<string, unknown> {
  const inForce = (v: ItemVersion): boolean => {
    if (!at) return true;
    const from = v.effective_from ? new Date(v.effective_from) : null;
    const until = v.effective_until ? new Date(v.effective_until) : null;
    if (from && at < from) return false;
    if (until && at >= until) return false;
    return true;
  };
  const candidate = [...item.versions].reverse().find(inForce);
  if (!candidate) return null as unknown as Record<string, unknown>;
  return renderVersion(item, candidate);
}

export function itemJson(item: Item): Record<string, unknown> {
  const view: Record<string, unknown> = {
    identifier: item.identifier,
    register: item.register,
    item_class: item.item_class,
    title: item.title,
  };
  if (item.submitting_organization)
    view.submitting_organization = item.submitting_organization;
  view.versions = item.versions.map((v) => renderVersion(item, v));
  if (item.manifest) view.manifest = item.manifest;
  return view;
}

export function itemView(item: Item, at: Date | null, asOf: Date): Record<string, unknown> {
  const view = itemJson(item);
  view.version = versionJson(item, at, asOf);
  view.as_of = asOf.toISOString().replace(/\.\d{3}Z$/, "Z");
  return view;
}

export function itemSummary(item: Item, at: Date | null, asOf: Date): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    identifier: item.identifier,
    register: item.register,
    item_class: item.item_class,
    title: item.title,
  };
  if (item.submitting_organization)
    summary.submitting_organization = item.submitting_organization;
  summary.version = versionJson(item, at, asOf);
  return summary;
}

// The point-in-time query instant: absent `at`/`asof` means the
// current registered state, not wall-clock now.
function parseAt(params: URLSearchParams): { at: Date | null; asOf: Date } {
  const raw = params.get("at") ?? params.get("asof");
  if (!raw || raw.trim() === "") return { at: null, asOf: new Date() };
  const at = new Date(raw);
  if (Number.isNaN(at.getTime())) throw new Error(`invalid \`at\` parameter: ${raw}`);
  return { at, asOf: at };
}

// The journal abstraction: append-only ops, replayed in order.
// workerd's SQLite-backed DO storage carries the sql API; the tests
// ride a plain map with the same contract.
export interface Journal {
  append(op: JournalOp): Promise<number>;
  all(): Promise<JournalOp[]>;
}

class SqlJournal implements Journal {
  private sql: {
    exec(query: string, ...params: unknown[]): { toArray(): unknown[] };
  };
  constructor(storage: { sql: unknown }) {
    this.sql = storage.sql as typeof this.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY, line TEXT)",
    );
  }
  async append(op: JournalOp): Promise<number> {
    const next = this.sql.exec("SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM journal")
      .toArray()[0] as { seq: number };
    this.sql.exec("INSERT INTO journal (seq, line) VALUES (?, ?)", next.seq, JSON.stringify(op));
    return next.seq as number;
  }
  async all(): Promise<JournalOp[]> {
    return this.sql
      .exec("SELECT line FROM journal ORDER BY seq")
      .toArray()
      .map((row) => JSON.stringify((row as { line: string }).line))
      .map((line) => JSON.parse(line) as JournalOp);
  }
}

class MapJournal implements Journal {
  private ops: JournalOp[] = [];
  constructor(private readonly storage: StoreLike) {}
  async append(op: JournalOp): Promise<number> {
    this.ops.push(op);
    await this.storage.put(`journal:${String(this.ops.length).padStart(6, "0")}`, op);
    return this.ops.length;
  }
  async all(): Promise<JournalOp[]> {
    const stored = await this.storage.list({ prefix: "journal:" });
    if (stored.size > 0) {
      this.ops = [...stored.entries()]
        .sort()
        .map(([, value]) => value as JournalOp);
    }
    return this.ops;
  }
}

interface StoreLike {
  put(key: string, value: unknown): Promise<void>;
  get(key: string): Promise<unknown>;
  list(options: { prefix: string }): Promise<Map<string, unknown>>;
}

// The journal: appended ops, replayed in order.
export class RegistryState {
  private items = new Map<string, Item>();
  private seq = 0;
  private loaded = false;

  constructor(private readonly journal: Journal) {}

  async load(): Promise<void> {
    if (this.loaded) return;
    for (const op of await this.journal.all()) {
      this.apply(op);
      this.seq += 1;
    }
    this.loaded = true;
  }

  private apply(op: JournalOp): void {
    if (op.op === "register-item") {
      const item = op.item as Item;
      this.items.set(item.identifier, item);
    } else if (op.op === "supersede-version") {
      const item = this.items.get(op.identifier as string);
      if (!item) return;
      const superseded = item.versions.find((v) => v.version === op.superseded_version);
      if (superseded && superseded.status === "valid") superseded.status = "superseded";
      if (superseded) superseded.superseded_by_version = op.successor_version as string;
      const successor = op.successor as ItemVersion;
      const existing = item.versions.find((v) => v.version === successor.version);
      if (!existing) item.versions.push(successor);
      if (op.manifest) item.manifest = op.manifest as Record<string, unknown>;
    }
  }

  async registerItem(item: Item): Promise<number> {
    const seq = await this.journal.append({ op: "register-item", item });
    this.seq = seq;
    this.apply({ op: "register-item", item });
    return seq;
  }

  async supersedeVersion(
    identifier: string,
    supersededVersion: string,
    successor: ItemVersion,
    manifest: Record<string, unknown> | null,
  ): Promise<number> {
    const item = this.items.get(identifier)!;
    const prior = item.versions.find((v) => v.version === supersededVersion)!;
    const seq = await this.journal.append({
      op: "supersede-version",
      identifier,
      superseded_version: supersededVersion,
      prior_status: prior.status,
      successor,
      manifest: manifest ?? undefined,
    } satisfies JournalOp);
    this.seq = seq;
    this.apply({
      op: "supersede-version",
      identifier,
      superseded_version: supersededVersion,
      successor_version: successor.version,
      successor,
      manifest: manifest ?? undefined,
    });
    return seq;
  }

  item(identifier: string): Item | undefined {
    return this.items.get(identifier);
  }

  allItems(): Item[] {
    return [...this.items.values()];
  }
}

export class RegistryDO {
  state: RegistryState;

  constructor(stateOrStorage: unknown) {
    // workerd hands the DurableObjectState; the tests hand a storage
    // stand-in. The SQL API lives on state.storage.
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    const sql = (source as { sql?: unknown }).sql;
    const journal: Journal = sql
      ? new SqlJournal(source as { sql: unknown })
      : new MapJournal(source as StoreLike);
    this.state = new RegistryState(journal);
  }

  async fetch(request: Request): Promise<Response> {
    await this.state.load();
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (path === "/items" && request.method === "GET") return this.list(url);
    if (path === "/items" && request.method === "POST") return this.create(request);
    const supersede = path.match(/^\/items\/([^/]+)\/versions$/);
    if (supersede && request.method === "POST") {
      return this.supersede(request, decodeURIComponent(supersede[1]), url);
    }
    const one = path.match(/^\/items\/([^/]+)$/);
    if (one && request.method === "GET") return this.getOne(url, decodeURIComponent(one[1]));
    return notFound("no such path");
  }

  private async list(url: URL): Promise<Response> {
    let params: URLSearchParams;
    try {
      params = url.searchParams;
      const { at, asOf } = parseAt(params);
      const classFilter = params.get("class");
      if (classFilter && !ITEM_CLASSES.includes(classFilter)) {
        return badRequest(`unknown item class \`${classFilter}\``);
      }
      const register = params.get("register");
      const items = this.state
        .allItems()
        .filter((i) => !classFilter || i.item_class === classFilter)
        .filter((i) => !register || i.register === register)
        .sort((a, b) => a.identifier.localeCompare(b.identifier))
        .map((i) => itemSummary(i, at, asOf));
      return stamped(
        200,
        {
          as_of: at ? at.toISOString().replace(/\.\d{3}Z$/, "Z") : isoNow(),
          count: items.length,
          items,
        },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  private async create(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const asOf = new Date();
    const register = (v.register_id as string)?.trim();
    const identifier = (v.item_id as string)?.trim();
    if (!register) return badRequest("`register_id` is required");
    if (!identifier) return badRequest("`item_id` is required");
    if (!tokenOk(identifier)) {
      return badRequest("`item_id` must be 1-256 characters without `/` or whitespace");
    }
    if (this.state.item(identifier)) {
      return badRequest(`item \`${identifier}\` already exists`);
    }
    const itemClass = (v.class as string | undefined) ?? "data-element";
    if (!ITEM_CLASSES.includes(itemClass)) {
      return badRequest(`unknown item class \`${itemClass}\``);
    }
    if (itemClass === "model") {
      return badRequest(
        "model items are deposited through POST /models (EXPRESS source + content hash + expressir validation)",
      );
    }
    const title = (v.definition as string | undefined) ?? (v.title as string | undefined);
    if (!title || !title.trim()) return badRequest("`definition` is required");
    const version = (v.version as string)?.trim();
    if (!version) return badRequest("`version` is required");
    if (!tokenOk(version)) {
      return badRequest("`version` must be 1-256 characters without `/` or whitespace");
    }
    const status = (v.status as string | undefined) ?? "valid";
    if (!STATUSES.includes(status)) return badRequest(`invalid \`status\` \`${status}\``);
    if (status !== "valid") {
      return badRequest(
        "a new item must be registered with status `valid`; supersession happens through POST /items/{id}/versions",
      );
    }
    const effectiveFrom = (v.effective_from as string | undefined) ?? isoNow();
    const effectiveUntil = (v.effective_until as string | undefined) ?? null;
    if (effectiveUntil && new Date(effectiveUntil) <= new Date(effectiveFrom)) {
      return badRequest("`effective_until` must be after `effective_from`");
    }
    const manifest = (v.manifest as Record<string, unknown> | undefined) ?? undefined;
    if (manifest) {
      const pinned = manifest["version"];
      if (pinned !== version) {
        return badRequest("manifest `version` must be pinned to a registered version of the item");
      }
    }
    const item: Item = {
      identifier,
      register,
      item_class: itemClass,
      title: title.trim(),
      submitting_organization: (v.submitting_organization as string | undefined)?.trim() || undefined,
      versions: [
        {
          version,
          status: "valid",
          effective_from: effectiveFrom,
          effective_until: effectiveUntil,
          registered_at: isoNow(),
          superseded_by_version: null,
          notes: null,
        },
      ],
      manifest,
    };
    const auditSeq = await this.state.registerItem(item);
    const body = itemView(item, null, asOf) as Record<string, unknown>;
    body.audit_seq = auditSeq;
    return stamped(201, body, isoNow());
  }

  private async getOne(url: URL, identifier: string): Promise<Response> {
    let params: URLSearchParams;
    try {
      params = url.searchParams;
      const { at, asOf } = parseAt(params);
      const item = this.state.item(identifier);
      if (!item) return notFound(`no registry item \`${identifier}\``);
      const resolved = versionJson(item, at, asOf);
      if (!resolved) {
        return notFound(`no version of \`${identifier}\` is in force as of the requested instant`);
      }
      return stamped(200, itemView(item, at, asOf), isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  private async supersede(request: Request, identifier: string, url: URL): Promise<Response> {
    void url;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const item = this.state.item(identifier);
    if (!item) return notFound(`no registry item \`${identifier}\``);
    const version = (v.version as string)?.trim();
    if (!version) return badRequest("`version` is required");
    if (!tokenOk(version)) {
      return badRequest("`version` must be 1-256 characters without `/` or whitespace");
    }
    const reason = (v.reason as string)?.trim();
    if (!reason) return badRequest("`reason` is required");
    const effectiveFrom = (v.effective_from as string | undefined) ?? isoNow();
    const effectiveUntil = (v.effective_until as string | undefined) ?? null;
    if (effectiveUntil && new Date(effectiveUntil) <= new Date(effectiveFrom)) {
      return badRequest("`effective_until` must be after `effective_from`");
    }
    if (item.versions.some((existing) => existing.version === version)) {
      return badRequest(`version \`${version}\` already exists on \`${identifier}\``);
    }
    const target = [...item.versions].reverse().find((existing) => existing.status === "valid");
    if (!target) {
      return badRequest(`\`${identifier}\` has no valid version to supersede`);
    }
    const manifest = (v.manifest as Record<string, unknown> | undefined) ?? undefined;
    const asOf = new Date();
    const successor: ItemVersion = {
      version,
      status: "valid",
      effective_from: effectiveFrom,
      effective_until: effectiveUntil,
      registered_at: isoNow(),
      superseded_by_version: null,
      notes: reason,
    };
    const auditSeq = await this.state.supersedeVersion(
      identifier,
      target.version,
      successor,
      manifest ?? null,
    );
    const after = this.state.item(identifier)!;
    const newVersion = after.versions.find((existing) => existing.version === version)!;
    const oldVersion = after.versions.find((existing) => existing.version === target.version)!;
    const newView = versionJson(after, null, asOf) && {
      ...versionJson(after, null, asOf),
      ...newVersion,
    };
    const body: Record<string, unknown> = {
      identifier,
      new_version: newView,
      superseded_version: oldVersion,
      item: itemJson(after),
      reason,
      audit_seq: auditSeq,
      as_of: isoNow(),
    };
    return stamped(201, body, isoNow());
  }
}

export function mountClass(): string {
  return CLASS_PLURALS["data-element"];
}
