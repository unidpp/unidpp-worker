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
  "class-descriptor",
  "instance",
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
  "class-descriptor": "class-descriptors",
  instance: "instances",
};

import { evalRule, parseRule, ruleDescriptorErrors } from "./rules";

// The R10 intake checks (clause 5): the class descriptor registers
// only in its signed form and declares its shape; an instance
// validates against the descriptor it names, point-in-time, and
// every refusal names the failing fact path.

const FACT_KINDS = ["string", "decimal", "boolean", "list"];
const CAPABILITY_CLASSES = ["silent", "passive-auth", "logged-contact", "connected"];
const ISSUER_CLASSES = ["law", "treaty", "consensus", "declaration", "attestation"];

export interface FeatureSpec {
  path: string;
  kind: string;
  required: boolean;
  vocabulary?: string[];
  unit?: string;
}

const validFactPath = (path: string): boolean =>
  path.length > 0 && path.split(".").every((segment) => segment.length > 0);

export function parseFeatureSpecs(
  manifest: Record<string, unknown>,
): { ok: true; specs: FeatureSpec[] } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const raw = manifest["features"];
  if (!Array.isArray(raw)) {
    return {
      ok: false,
      errors: ["the descriptor declares its features as an array of feature specs"],
    };
  }
  const specs: FeatureSpec[] = [];
  raw.forEach((feature: Record<string, unknown>, index: number) => {
    const at = `manifest.features[${index}]`;
    const path = typeof feature["path"] === "string" ? feature["path"] : null;
    if (!path) {
      errors.push(`${at}.path: every feature names its dotted fact path`);
      return;
    }
    if (!validFactPath(path)) {
      errors.push(`${at}.path: \`${path}\` is not a fact path (dotted segments, no empty segment)`);
    }
    const kind = typeof feature["kind"] === "string" ? feature["kind"] : "";
    if (!FACT_KINDS.includes(kind)) {
      errors.push(`${at}.kind: \`${kind}\` is not a value kind (the closed set: ${FACT_KINDS.join(", ")})`);
    }
    const vocabulary = Array.isArray(feature["vocabulary"])
      ? (feature["vocabulary"] as unknown[]).filter((v): v is string => typeof v === "string")
      : undefined;
    const unit = typeof feature["unit"] === "string" ? feature["unit"] : undefined;
    if (vocabulary && kind !== "string") {
      errors.push(`${at}.vocabulary: a vocabulary declares the range of a STRING feature`);
    }
    if (unit && kind !== "decimal") {
      errors.push(`${at}.unit: a unit reference declares the unit of a DECIMAL feature`);
    }
    if (vocabulary && vocabulary.length === 0) {
      errors.push(`${at}.vocabulary: a declared vocabulary states its members`);
    }
    if (unit !== undefined && !unit.trim()) {
      errors.push(`${at}.unit: the unit reference is empty`);
    }
    specs.push({
      path,
      kind,
      required: feature["required"] === true,
      vocabulary,
      unit,
    });
  });
  const seen = new Set<string>();
  for (const spec of specs) {
    if (seen.has(spec.path)) {
      errors.push(`manifest.features: the fact path \`${spec.path}\` is declared twice`);
    }
    seen.add(spec.path);
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, specs };
}

// The signed form a class descriptor registers under (the same
// discipline a profile manifest carries; the cryptographic reading
// is the trust service's).
export function descriptorSignatureErrors(manifest: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const issuerClass = manifest["issuer_class"];
  if (typeof issuerClass !== "string" || !ISSUER_CLASSES.includes(issuerClass)) {
    errors.push(
      `manifest.issuer_class: \`${String(issuerClass)}\` is not an issuer class (one of ${ISSUER_CLASSES.join(", ")})`,
    );
  }
  const issuer = manifest["issuer"];
  if (typeof issuer !== "string" || !issuer.trim()) {
    errors.push("manifest.issuer: the issuing node's id is required (the signer of record)");
  }
  const signature = (manifest["signature"] as Record<string, unknown> | undefined)?.["signature"];
  if (typeof signature !== "string" || !signature.trim()) {
    errors.push(
      "manifest.signature: class descriptors register only in their SIGNED form (a signature slot with a signature value)",
    );
  }
  return errors;
}

export function descriptorManifestErrors(
  identifier: string,
  manifest: Record<string, unknown>,
): string[] {
  const errors: string[] = [];
  const classId = manifest["class_id"];
  if (typeof classId !== "string" || !classId) {
    errors.push("manifest.class_id: the descriptor states its class_id (the identifier names the class)");
  } else if (classId !== identifier) {
    errors.push(
      `manifest.class_id: the descriptor's class_id \`${classId}\` must name the item itself (\`${identifier}\`)`,
    );
  }
  const parsed = parseFeatureSpecs(manifest);
  if (!parsed.ok) {
    errors.push(...parsed.errors);
  } else if (parsed.specs.length === 0) {
    errors.push("manifest.features: a class descriptor declares at least one feature");
  }
  const capabilityClasses = manifest["capability_classes"];
  if (!Array.isArray(capabilityClasses) || capabilityClasses.length === 0) {
    errors.push(
      "manifest.capability_classes: the descriptor states at least one capability class (S0-S3)",
    );
  } else {
    capabilityClasses.forEach((token, index) => {
      if (typeof token !== "string" || !CAPABILITY_CLASSES.includes(token)) {
        errors.push(
          `manifest.capability_classes[${index}]: \`${String(token)}\` is not a capability class (one of ${CAPABILITY_CLASSES.join(", ")})`,
        );
      }
    });
  }
  // The rule references' deterministic reading (G4): every
  // reference resolves to a declared rule, and each expression
  // parses and reads only declared features with compatible kinds.
  const declaredRules = new Map<string, string>();
  const rules = manifest["rules"];
  if (rules !== undefined && !Array.isArray(rules)) {
    errors.push("manifest.rules: the descriptor declares its rules as an array of {id, expr}");
  } else if (Array.isArray(rules)) {
    rules.forEach((rule, index) => {
      const record = rule as Record<string, unknown>;
      const id = typeof record["id"] === "string" ? record["id"].trim() : "";
      const expression = typeof record["expr"] === "string" ? record["expr"] : "";
      if (!id) {
        errors.push(`manifest.rules[${index}].id: a rule states its id`);
        return;
      }
      if (declaredRules.has(id)) {
        errors.push(`manifest.rules[${index}].id: the rule id \`${id}\` is declared twice`);
      }
      declaredRules.set(id, expression);
      const parsed = parseRule(expression);
      if (!parsed.ok) {
        errors.push(
          `manifest.rules[${index}].expr: the expression does not parse: at offset ${parsed.error.offset}, ${parsed.error.message}`,
        );
        return;
      }
      const kinds = new Map<string, string>();
      const specs = parseFeatureSpecs(manifest);
      if (specs.ok) {
        for (const spec of specs.specs) kinds.set(spec.path, spec.kind);
      }
      for (const message of ruleDescriptorErrors(parsed.expr, kinds)) {
        errors.push(`manifest.rules[${index}].expr: ${message}`);
      }
    });
  }
  const ruleReferences = manifest["rule_references"];
  if (!Array.isArray(ruleReferences)) {
    errors.push(
      "manifest.rule_references: the descriptor states the rule references it relies on (an empty array declares none)",
    );
  } else {
    ruleReferences.forEach((token, index) => {
      if (typeof token !== "string" || !token.trim()) {
        errors.push(`manifest.rule_references[${index}]: a rule reference is a non-empty rule id`);
        return;
      }
      if (!declaredRules.has(token)) {
        errors.push(
          `manifest.rule_references[${index}]: the rule reference \`${token}\` names no rule the descriptor declares in \`rules\``,
        );
      }
    });
  }
  return errors;
}

// The instance against its descriptor (point-in-time; the open map
// rides unvalidated).
export function instanceErrors(
  identifier: string,
  manifest: Record<string, unknown>,
  store: RegistryState,
): string[] {
  const classId = typeof manifest["instance_of"] === "string" ? manifest["instance_of"].trim() : "";
  if (!classId) {
    return [
      "manifest.instance_of: the instance states the class it instantiates (the descriptor's identifier)",
    ];
  }
  const descriptor = store.item(classId);
  if (!descriptor || descriptor.item_class !== "class-descriptor" || !descriptor.manifest) {
    return [
      descriptor
        ? `manifest.instance_of: \`${classId}\` is registered as a ${descriptor.item_class}, not a class descriptor`
        : `manifest.instance_of: unknown class \`${classId}\`: no registered class descriptor names it`,
    ];
  }
  const parsed = parseFeatureSpecs(descriptor.manifest);
  if (!parsed.ok) {
    return [
      `manifest.instance_of: the class descriptor \`${classId}\` itself does not parse: ${parsed.errors.join("; ")}`,
    ];
  }
  const features = (manifest["features"] ?? {}) as Record<string, unknown>;
  // The referenced rules read deterministically (G4): every
  // referenced rule evaluates over the instance's facts; a failing
  // rule names its id and its expression.
  const declaredRules = new Map<string, string>();
  const declared = descriptor.manifest["rules"];
  if (Array.isArray(declared)) {
    for (const rule of declared as Record<string, unknown>[]) {
      const id = typeof rule["id"] === "string" ? rule["id"] : "";
      const expression = typeof rule["expr"] === "string" ? rule["expr"] : "";
      if (id) declaredRules.set(id, expression);
    }
  }
  const errors = instanceAgainstSpecs(classId, parsed.specs, features, store);
  for (const reference of (descriptor.manifest["rule_references"] as string[] | undefined) ?? []) {
    const expression = declaredRules.get(reference);
    if (!expression) continue; // the descriptor intake refuses dangling references
    const parsed = parseRule(expression);
    if (parsed.ok && !evalRule(parsed.expr, features)) {
      errors.push(
        `manifest.rule_references.${reference}: the rule \`${reference}\` of the class \`${classId}\` is not satisfied: ${expression}`,
      );
    }
  }
  return errors;
}

// The pure instance validation (the designer's draft path runs the
// same rules against an unregistered descriptor's specs). The unit
// check rides only when the caller resolves against a register
// (checkUnits=false in the workbench, where the references are
// stated as unverified).
export function instanceAgainstSpecs(
  classId: string,
  specs: FeatureSpec[],
  features: Record<string, unknown>,
  store: Pick<RegistryState, "item">,
  checkUnits = true,
): string[] {
  const errors: string[] = [];
  const valueKind = (value: unknown): string | null => {
    if (typeof value === "string") return "string";
    if (typeof value === "boolean") return "boolean";
    if (typeof value === "number") return "decimal";
    if (Array.isArray(value) && value.every((v) => typeof v === "string")) return "list";
    return null;
  };
  for (const spec of specs) {
    const fact = features[spec.path];
    if (fact === undefined || fact === null) {
      if (spec.required) {
        errors.push(
          `manifest.features.${spec.path}: the class \`${classId}\` declares \`${spec.path}\` required; the instance states no fact at that path (missing-required)`,
        );
      }
      continue;
    }
    const presented = valueKind(fact);
    if (presented !== spec.kind) {
      errors.push(
        `manifest.features.${spec.path}: the fact presents as ${presented ?? "neither string, decimal, boolean nor a list of strings"}; the class \`${classId}\` declares \`${spec.kind}\` (wrong-kind)`,
      );
      continue;
    }
    if (spec.vocabulary) {
      const member = fact as string;
      if (!spec.vocabulary.includes(member)) {
        errors.push(
          `manifest.features.${spec.path}: \`${member}\` is outside the vocabulary the class \`${classId}\` declares (out-of-vocabulary; members: ${spec.vocabulary.join(", ")})`,
        );
      }
    }
  }
  for (const spec of specs) {
    if (!spec.unit || !checkUnits) continue;
    const unitItem = store.item(spec.unit);
    if (!unitItem || unitItem.item_class !== "unit") {
      errors.push(
        `manifest.features.${spec.path}: the class \`${classId}\` declares unit \`${spec.unit}\` for \`${spec.path}\`, but no registered unit names it (unresolved-unit)`,
      );
    }
  }
  return errors;
}

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

export interface Journal {
  append(op: JournalOp): Promise<number>;
  all(): Promise<JournalOp[]>;
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
    if (path === "/discovery" && request.method === "GET") {
      const descriptors = this.state
        .allItems()
        .filter((i) => i.item_class === "class-descriptor")
        .map((i) => {
          const parsed = i.manifest ? parseFeatureSpecs(i.manifest) : null;
          const specs = parsed && parsed.ok ? parsed.specs : [];
          return {
            class_id: i.identifier,
            title: i.title,
            register: i.register,
            features: specs.map((f) => ({
              path: f.path,
              kind: f.kind,
              required: f.required,
              vocabulary: f.vocabulary ?? null,
              unit: f.unit ?? null,
            })),
            subregister: "/class-descriptors",
          };
        });
      return stamped(200, {
        service: "unidpp-registry",
        class_descriptors: descriptors,
        subregisters: Object.fromEntries(
          ITEM_CLASSES.map((c) => [
            CLASS_PLURALS[c] ?? c,
            { class: c, path: `/${CLASS_PLURALS[c] ?? c}` },
          ]),
        ),
        as_of: isoNow(),
      }, isoNow());
    }
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
    // The generic subregister mount (the native registry's
    // `/{class}/{id}`): the same item read, class-filtered.
    const sub = path.match(/^\/([a-z-]+)\/([^/]+)$/);
    if (sub && request.method === "GET") {
      const className = sub[1];
      const singular = Object.entries(CLASS_PLURALS).find(([, plural]) => plural === className)?.[0];
      if (!singular && !ITEM_CLASSES.includes(className)) {
        return notFound("no such path");
      }
      const itemClass = singular ?? className;
      return this.getOneScoped(url, decodeURIComponent(sub[2]), itemClass);
    }
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
    // The class-scoped intake checks (clause 5; R10 B1 + B2): the
    // descriptor's signed form and shape, the instance against its
    // descriptor. Refusals name the failing paths.
    if (itemClass === "class-descriptor" || itemClass === "instance") {
      const scoped = itemClass === "class-descriptor"
        ? [
            ...descriptorSignatureErrors(manifest ?? {}),
            ...descriptorManifestErrors(identifier, manifest ?? {}),
          ]
        : instanceErrors(identifier, manifest ?? {}, this.state);
      if (scoped.length > 0) {
        return badRequest(scoped.join("; "));
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

  private async getOneScoped(url: URL, identifier: string, itemClass: string): Promise<Response> {
    const response = await this.getOne(url, identifier).catch((e) => {
      throw e;
    });
    // The body is single-read: clone for the class check, serve the
    // original.
    const body = (await (response.clone()).json()) as { item_class?: string };
    if (body.item_class !== itemClass) {
      return notFound(`no registry item \`${identifier}\``);
    }
    return response;
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
    if (manifest) {
      const pinned = manifest["version"];
      if (pinned !== version) {
        return badRequest("manifest `version` must be pinned to a registered version of the item");
      }
      // The same class-scoped checks gate a superseding manifest.
      if (item.item_class === "class-descriptor" || item.item_class === "instance") {
        const scoped = item.item_class === "class-descriptor"
          ? [
              ...descriptorSignatureErrors(manifest),
              ...descriptorManifestErrors(identifier, manifest),
            ]
          : instanceErrors(identifier, manifest, this.state);
        if (scoped.length > 0) {
          return badRequest(scoped.join("; "));
        }
      }
    }
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
