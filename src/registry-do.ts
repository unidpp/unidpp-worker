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
import { SqlJournal, MapJournal, type Journal, type JournalOp } from "./journal";
export type { JournalOp };

// ---------------------------------------------------------------------------
// The discovery layer (C3 services, C4 protocol bindings, C5
// verification mechanisms) and the dated applicability bindings. The
// intake verifies what the edge can verify structurally — the
// operator id's derivation from its public key, the signature block's
// shape, the body's required fields; the cryptographic verification
// rides the operator keyring, which the edge does not carry, so the
// signatures are stored as presented and re-applied on replay.
// ---------------------------------------------------------------------------

const SERVICE_CLASSES = [
  "issuer",
  "registry",
  "resolver",
  "trust",
  "log",
  "archive",
  "gateway",
  "marketplace-gate",
  "edge",
];

const SERVICE_STATUSES = ["active", "superseded", "suspended", "succeeded"];

interface DiscoverySignature {
  key_id: string;
  algorithm: string;
  value: string;
}

interface ServiceVersionRec {
  version: string;
  status: string;
  effective_from: string;
  effective_until: string | null;
  registered_at: string;
  superseded_by_version: string | null;
  body: Record<string, unknown>;
  signature: DiscoverySignature;
}

interface ServiceDescriptorRec {
  identifier: string;
  versions: ServiceVersionRec[];
}

interface ProtocolBindingRec {
  identifier: string;
  grammar_ref: string;
  media_types: string[];
  version: string;
  conformance_suite_ref: string | null;
  body: Record<string, unknown>;
  signature: DiscoverySignature;
}

interface VerificationMechanismRec {
  identifier: string;
  suite: string;
  agility_status: string;
  trust_framework: string | null;
  trust_list_endpoint: string | null;
  master_list_ref: string | null;
  verdict_grammar_ref: string | null;
  body: Record<string, unknown>;
  signature: DiscoverySignature;
}

// The dated applicability binding (Ruby `ApplicabilityBinding`): a
// profile item bound to a subject with an effective window and the
// retroactivity flag — a retroactive binding legally backdates to its
// `effective_from`, a non-retroactive one binds only from its
// `registered_at`.
export interface ApplicabilityBinding {
  id: number;
  subject: string;
  profile_item: string;
  register: string | null;
  profile_version: string | null;
  effective_from: string | null;
  effective_until: string | null;
  registered_at: string | null;
  retroactive: boolean;
}

// One hex string of exactly `bytes` bytes, or null.
const hexDecode = (value: string, bytes: number): string | null => {
  if (value.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(value)) return null;
  if (value.length !== bytes * 2) return null;
  return value.toLowerCase();
};

const sha256Hex = async (parts: (string | Uint8Array)[]): Promise<string> => {
  const encoded = parts.map((part) =>
    typeof part === "string" ? new TextEncoder().encode(part) : part,
  );
  const length = encoded.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of encoded) {
    joined.set(part, offset);
    offset += part.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", joined);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

// The content-derived operator id (`op-` + 16 hex of H("op" || pk))
// and key id (`k-` + 16 hex of H("key" || pk)) — the checks the
// intake runs without the keyring. The hash reads the KEY BYTES, not
// their hex spelling.
const operatorIdOf = async (publicKey: string): Promise<string> => {
  const bytes = hexDecode(publicKey, 32);
  if (bytes === null) return "op-0000000000000000";
  return `op-${(await sha256Hex(["op", hexToBytes(bytes)])).slice(0, 16)}`;
};

const operatorKeyIdOf = async (publicKey: string): Promise<string> => {
  const bytes = hexDecode(publicKey, 32);
  if (bytes === null) return "k-0000000000000000";
  return `k-${(await sha256Hex(["key", hexToBytes(bytes)])).slice(0, 16)}`;
};

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from({ length: hex.length / 2 }, (_, i) =>
    parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  );

// The wire signature block (Ed25519 only — the discovery layer pins
// one suite per descriptor).
function signatureFromJson(v: unknown): DiscoverySignature {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("signature must be an object");
  }
  const keyId = obj["key_id"];
  if (typeof keyId !== "string") throw new Error("missing `key_id`");
  const algorithm = obj["algorithm"];
  if (typeof algorithm !== "string") throw new Error("missing `algorithm`");
  if (algorithm !== "ed25519") {
    throw new Error(
      `unsupported signature algorithm \`${algorithm}\` (only \`ed25519\` is accepted)`,
    );
  }
  const value = obj["value"];
  if (typeof value !== "string") throw new Error("missing `value`");
  if (hexDecode(value, 64) === null) {
    if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
      throw new Error(`\`value\` is not a hex string: \`${value}\``);
    }
    throw new Error(
      `Ed25519 signature must be 64 bytes (got ${value.length / 2})`,
    );
  }
  return { key_id: keyId, algorithm, value };
}

// The operator identity block inside a descriptor body: the id must
// be the content-derived id of the public key (the trust anchor).
async function operatorFromJson(
  v: unknown,
): Promise<{ id: string; public_key: string }> {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("operator must be an object");
  }
  const id = obj["id"];
  if (typeof id !== "string" || id === "") {
    throw new Error("missing `operator.id`");
  }
  const hex = obj["public_key"];
  if (typeof hex !== "string") throw new Error("missing `operator.public_key`");
  const publicKey = hexDecode(hex, 32);
  if (publicKey === null) {
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
      throw new Error(`\`operator.public_key\` is not a hex string: \`${hex}\``);
    }
    throw new Error(
      `Ed25519 public key must be 32 bytes (got ${hex.length / 2})`,
    );
  }
  const derived = await operatorIdOf(publicKey);
  if (id !== derived) {
    throw new Error(
      `operator id \`${id}\` does not match the content-derived id \`${derived}\` for the public key`,
    );
  }
  return { id, public_key: publicKey };
}

interface EndpointRec {
  uri: string;
  protocol_binding_ref: string | null;
}

function endpointFromJson(v: unknown): EndpointRec {
  const obj = v as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("endpoint must be an object");
  }
  const uri = obj["uri"];
  if (typeof uri !== "string" || uri === "") {
    throw new Error("missing `uri`");
  }
  const ref = obj["protocol_binding_ref"];
  if (ref === undefined || ref === null) {
    return { uri, protocol_binding_ref: null };
  }
  if (typeof ref !== "string") {
    throw new Error("`protocol_binding_ref` must be a string");
  }
  return { uri, protocol_binding_ref: ref === "" ? null : ref };
}

interface ServiceBodyRec {
  status: string;
  operator: { id: string; public_key: string };
}

// Parses the wire body of a service descriptor (the inner object that
// gets signed) and validates its structural shape.
async function parseServiceBody(
  body: unknown,
  identifier: string,
): Promise<ServiceBodyRec> {
  const obj = body as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("body must be an object");
  }
  const serviceClass = obj["class"];
  if (typeof serviceClass !== "string") {
    throw new Error("body missing `class`");
  }
  if (!SERVICE_CLASSES.includes(serviceClass)) {
    throw new Error(
      `unknown service class \`${serviceClass}\` (expected one of ${SERVICE_CLASSES.join(", ")})`,
    );
  }
  const operator = await operatorFromJson(obj["operator"]).catch((e) => {
    if (
      (e as Error).message === "body missing `operator`" ||
      obj["operator"] === undefined
    ) {
      throw new Error("body missing `operator`");
    }
    throw e;
  });
  const endpointsVal = obj["endpoints"];
  if (endpointsVal === undefined) {
    throw new Error("body missing `endpoints`");
  }
  if (!Array.isArray(endpointsVal)) {
    throw new Error("`endpoints` must be an array");
  }
  const endpoints = endpointsVal.map(endpointFromJson);
  if (endpoints.length === 0) {
    throw new Error("`endpoints` must not be empty");
  }
  let status = "active";
  const statusVal = obj["status"];
  if (statusVal !== undefined && statusVal !== null) {
    if (typeof statusVal !== "string") {
      throw new Error("`status` must be a string");
    }
    if (!SERVICE_STATUSES.includes(statusVal)) {
      throw new Error(`unknown \`status\` value \`${statusVal}\``);
    }
    status = statusVal;
  }
  const bodyId = typeof obj["identifier"] === "string" ? obj["identifier"] : identifier;
  if (bodyId !== identifier) {
    throw new Error(
      `body \`identifier\` \`${bodyId}\` does not match the path identifier \`${identifier}\``,
    );
  }
  return { status, operator };
}

function parseProtocolBody(body: unknown): {
  grammar_ref: string;
  media_types: string[];
  conformance_suite_ref: string | null;
} {
  const obj = body as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("body must be an object");
  }
  const grammarRef = obj["grammar_ref"];
  if (typeof grammarRef !== "string" || grammarRef === "") {
    throw new Error("body missing `grammar_ref`");
  }
  const mediaTypes = Array.isArray(obj["media_types"])
    ? (obj["media_types"] as unknown[]).filter(
        (m): m is string => typeof m === "string",
      )
    : [];
  if (mediaTypes.length === 0) {
    throw new Error("body missing `media_types`");
  }
  const conformance = obj["conformance_suite_ref"];
  return {
    grammar_ref: grammarRef,
    media_types: mediaTypes,
    conformance_suite_ref:
      typeof conformance === "string" ? conformance : null,
  };
}

function parseVerificationBody(body: unknown): {
  suite: string;
  agility_status: string;
  trust_framework: string | null;
  trust_list_endpoint: string | null;
  master_list_ref: string | null;
  verdict_grammar_ref: string | null;
} {
  const obj = body as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("body must be an object");
  }
  const req = (key: string): string => {
    const value = obj[key];
    if (typeof value !== "string" || value === "") {
      throw new Error(`body missing \`${key}\``);
    }
    return value;
  };
  const opt = (key: string): string | null => {
    const value = obj[key];
    return typeof value === "string" ? value : null;
  };
  return {
    suite: req("suite"),
    agility_status: req("agility_status"),
    trust_framework: opt("trust_framework"),
    trust_list_endpoint: opt("trust_list_endpoint"),
    master_list_ref: opt("master_list_ref"),
    verdict_grammar_ref: opt("verdict_grammar_ref"),
  };
}

// ---------------------------------------------------------------------------
// Clock predicates (T-02): a profile's time triggers
// (`{predicate_class: "time", basis, operator, duration}`) evaluated
// at the query instant — `basis + duration <operator> at`, with the
// month arithmetic calendar-aware (a month added to January 31 lands
// on the last day of February).
// ---------------------------------------------------------------------------

const TRIGGER_BASES = ["manufactured_at", "first_registered_at"];
const TRIGGER_OPERATORS = [">=", ">", "<=", "<"];
const SECS_PER_DAY = 86_400;

const isLeapYear = (year: number): boolean =>
  (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;

const daysInMonth = (year: number, month: number): number => {
  if ([1, 3, 5, 7, 8, 10, 12].includes(month)) return 31;
  if ([4, 6, 9, 11].includes(month)) return 30;
  return isLeapYear(year) ? 29 : 28;
};

// Howard Hinnant's days_from_civil / civil_from_days (proleptic
// Gregorian) — the exact integer calendar the native keeps.
const daysFromCivil = (year: number, month: number, day: number): number => {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = month > 2 ? month - 3 : month + 9;
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146_097 + doe - 719_468;
};

const civilFromDays = (z: number): [number, number, number] => {
  const shifted = z + 719_468;
  const era = Math.floor(shifted / 146_097);
  const doe = shifted - era * 146_097;
  const yoe = Math.floor(
    (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365,
  );
  const year = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp < 10 ? mp + 3 : mp - 9;
  return [month <= 2 ? year + 1 : year, month, day];
};

const rfc3339 = (secs: number): string =>
  new Date(secs * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

// An ISO 8601 duration, normalized into calendar months plus absolute
// seconds (`P40Y` → 480 months; `P2W` → 14 days).
function parseIsoDuration(input: string): { months: number; seconds: number } {
  const invalid = () =>
    `invalid ISO 8601 duration \`${input}\` (expected e.g. P40Y, P1Y6M3D, PT6H30M)`;
  if (!input.startsWith("P")) throw new Error(invalid());
  const [datePart, timePart] = input.slice(1).split("T", 2);
  if (input.slice(1).includes("T") && timePart === undefined) {
    throw new Error(invalid());
  }
  let months = 0;
  let seconds = 0;
  let seen = false;
  const take = (rest: string, unit: string): [number, string] | null => {
    const match = rest.match(/^(\d+)([YMWDHMS])/);
    if (!match || match[2] !== unit) return null;
    return [Number(match[1]), rest.slice(match[0].length)];
  };
  let rest = datePart;
  for (const [unit, apply] of [
    ["Y", (n: number) => (months += n * 12)],
    ["M", (n: number) => (months += n)],
    ["W", (n: number) => (seconds += n * 7 * SECS_PER_DAY)],
    ["D", (n: number) => (seconds += n * SECS_PER_DAY)],
  ] as const) {
    const taken = take(rest, unit);
    if (taken) {
      apply(taken[0]);
      rest = taken[1];
      seen = true;
    }
  }
  if (rest !== "") throw new Error(invalid());
  if (timePart !== undefined) {
    let trest = timePart;
    for (const [unit, secsPer] of [
      ["H", 3600],
      ["M", 60],
      ["S", 1],
    ] as const) {
      const taken = take(trest, unit);
      if (taken) {
        seconds += taken[0] * secsPer;
        trest = taken[1];
        seen = true;
      }
    }
    if (trest !== "" || timePart === "") throw new Error(invalid());
  }
  if (!seen || (datePart === "" && timePart === undefined)) {
    throw new Error(invalid());
  }
  return { months, seconds };
}

// Adds a duration to an epoch second, calendar-aware: year/month
// components in the civil calendar (the day clamped to the target
// month's last day), day/time components in absolute seconds.
function addDuration(secs: number, duration: { months: number; seconds: number }): number {
  if (duration.months === 0) return secs + duration.seconds;
  const days = Math.floor(secs / SECS_PER_DAY);
  const timeOfDay = secs - days * SECS_PER_DAY;
  const [year, month, day] = civilFromDays(days);
  const total = year * 12 + (month - 1) + duration.months;
  const newYear = Math.floor(total / 12);
  const newMonth = (total % 12) + 1;
  const newDay = Math.min(day, daysInMonth(newYear, newMonth));
  return (
    daysFromCivil(newYear, newMonth, newDay) * SECS_PER_DAY + timeOfDay + duration.seconds
  );
}

interface TimeTrigger {
  basis: string;
  operator: string;
  duration: { months: number; seconds: number };
  duration_raw: string;
}

// Parses one trigger object into a TimeTrigger (the native's strict
// basis/operator vocabulary and duration form).
function parseTimeTrigger(trigger: unknown): TimeTrigger {
  const obj = trigger as Record<string, unknown> | null;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("time trigger must be an object");
  }
  const get = (key: string): string => {
    const value = obj[key];
    if (typeof value !== "string" || value === "") {
      throw new Error(`time trigger missing \`${key}\``);
    }
    return value;
  };
  const basis = get("basis");
  if (!TRIGGER_BASES.includes(basis)) {
    throw new Error(
      `time trigger \`basis\` \`${basis}\` is not one of ${TRIGGER_BASES.join(", ")}`,
    );
  }
  const operator = get("operator");
  if (!TRIGGER_OPERATORS.includes(operator)) {
    throw new Error(
      `time trigger \`operator\` \`${operator}\` is not one of ${TRIGGER_OPERATORS.join(", ")}`,
    );
  }
  const durationRaw = get("duration");
  return {
    basis,
    operator,
    duration: parseIsoDuration(durationRaw),
    duration_raw: durationRaw,
  };
}

// The manifest's time triggers (other predicate classes ride
// unvalidated; fact predicates are evaluated by the subject's
// custodian, never here).
function timeTriggers(manifest: Record<string, unknown>): [number, TimeTrigger][] {
  const out: [number, TimeTrigger][] = [];
  const triggers = manifest["triggers"];
  if (!Array.isArray(triggers)) return out;
  triggers.forEach((trigger, index) => {
    if (
      (trigger as Record<string, unknown>)["predicate_class"] === "time"
    ) {
      out.push([index, parseTimeTrigger(trigger)]);
    }
  });
  return out;
}

// Evaluates one trigger against the subject facts at the instant: the
// predicate holds iff `at <operator> basis + duration`. A missing or
// unparseable basis fact is an error (the caller decides whether that
// means "does not bind").
function evaluateTrigger(
  trigger: TimeTrigger,
  facts: Record<string, unknown>,
  atSecs: number,
): { threshold: string; satisfied: boolean } {
  const raw = facts[trigger.basis];
  if (typeof raw !== "string") {
    throw new Error(`subject facts missing the \`${trigger.basis}\` basis`);
  }
  const basisSecs = new Date(raw).getTime();
  if (Number.isNaN(basisSecs)) {
    throw new Error(
      `subject fact \`${trigger.basis}\`: invalid timestamp \`${raw}\` (expected RFC 3339 UTC)`,
    );
  }
  const threshold = addDuration(Math.floor(basisSecs / 1000), trigger.duration);
  const satisfied =
    trigger.operator === ">="
      ? atSecs >= threshold
      : trigger.operator === ">"
        ? atSecs > threshold
        : trigger.operator === "<="
          ? atSecs <= threshold
          : atSecs < threshold;
  return { threshold: rfc3339(threshold), satisfied };
}

// ---------------------------------------------------------------------------
// The generated JSON Schema (draft 2020-12) of a profile manifest —
// what GET /schemas/profile-manifest serves. The `as_of` member is
// serving metadata, not a validation keyword; the schema version
// rides in `$id`.
// ---------------------------------------------------------------------------

const SCHEMA_CAPABILITY_CLASSES = ["S0", "S1", "S2", "S3"];
const SCHEMA_AXES = ["jurisdiction", "sector", "characteristic"];
const SCHEMA_PREDICATE_CLASSES = ["fact_predicate", "time"];
const SCHEMA_GRANULARITIES = ["type", "lot", "instance"];
const CARDINALITY_PATTERN = "^[0-9]+(\\.\\.([0-9]+|n))?$";
const SCHEMA_DURATION_PATTERN =
  "^P(?!$)([0-9]+Y)?([0-9]+M)?([0-9]+W)?([0-9]+D)?(T(?=[0-9])([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$";

function profileManifestSchema(): Record<string, unknown> {
  const nonEmpty = { type: "string", minLength: 1 };
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://unidpp.org/schemas/profile-manifest/v1",
    title: "UniDPP profile manifest",
    description:
      "A profile is a registered, versioned lens on the neutral core. " +
      "The manifest binds axes, trigger predicates, the declared subject capability class, " +
      "legal basis, and the data points the profile requires. Generated from the canonical " +
      "Rust model (unidpp-registry src/manifest.rs); unknown fields are allowed.",
    type: "object",
    required: ["version"],
    properties: {
      version: nonEmpty,
      subject_capability: { type: "string", enum: SCHEMA_CAPABILITY_CLASSES },
      axes: { type: "array", items: { type: "string", enum: SCHEMA_AXES } },
      legal_basis: { type: "array", items: { $ref: "#/$defs/legal_basis" } },
      data_points: { type: "array", items: { $ref: "#/$defs/data_point" } },
      transforms: { type: "array", items: { $ref: "#/$defs/transform" } },
      triggers: { type: "array", items: { $ref: "#/$defs/trigger" } },
    },
    additionalProperties: true,
    $defs: {
      legal_basis: {
        type: "object",
        required: ["instrument", "citation", "force"],
        properties: {
          instrument: nonEmpty,
          citation: nonEmpty,
          force: nonEmpty,
        },
        additionalProperties: true,
      },
      data_point: {
        type: "object",
        required: ["element", "min_capability"],
        properties: {
          element: nonEmpty,
          min_capability: { type: "string", enum: SCHEMA_CAPABILITY_CLASSES },
          cardinality: { type: "string", pattern: CARDINALITY_PATTERN },
          required_provenance: nonEmpty,
          required_unit: nonEmpty,
          subject_granularity: { type: "string", enum: SCHEMA_GRANULARITIES },
          tier_a: { type: "boolean" },
          traversal_depth: { type: "integer", minimum: 0 },
          trust_floor: nonEmpty,
          fresh_within: { type: "string", pattern: SCHEMA_DURATION_PATTERN },
          visibility: nonEmpty,
        },
        additionalProperties: true,
      },
      transform: {
        type: "object",
        properties: {
          transform_ref: nonEmpty,
          transform_class: nonEmpty,
          method_citation: nonEmpty,
          decision_rule: nonEmpty,
          uncertainty_ref: nonEmpty,
        },
        additionalProperties: true,
      },
      trigger: {
        type: "object",
        required: ["predicate_class"],
        properties: {
          predicate_class: { type: "string", enum: SCHEMA_PREDICATE_CLASSES },
          predicate_ref: nonEmpty,
          evaluation_mode: nonEmpty,
          description: nonEmpty,
          basis: { type: "string", enum: TRIGGER_BASES },
          operator: { type: "string", enum: TRIGGER_OPERATORS },
          duration: { type: "string", pattern: SCHEMA_DURATION_PATTERN },
        },
        additionalProperties: true,
        allOf: [
          {
            if: {
              properties: { predicate_class: { const: "fact_predicate" } },
              required: ["predicate_class"],
            },
            then: { required: ["predicate_ref"] },
          },
          {
            if: {
              properties: { predicate_class: { const: "time" } },
              required: ["predicate_class"],
            },
            then: { required: ["basis", "operator", "duration"] },
          },
        ],
      },
    },
  };
}

// ---------------------------------------------------------------------------
// The seed dataset's discovery corpus (C3/C4/C5): the release's
// deterministic dev-keyring descriptors — fixed bodies signed by the
// operators' derived keys, so the records (and their signature
// blocks) are constants of the native seed. `registered_at` rides the
// seed run, not the corpus.
// ---------------------------------------------------------------------------

interface SeedProtocolBinding {
  kind: "pb";
  body: Record<string, unknown>;
  signature: DiscoverySignature;
}

interface SeedVerificationMechanism {
  kind: "vm";
  body: Record<string, unknown>;
  signature: DiscoverySignature;
}

interface SeedService {
  kind: "service";
  identifier: string;
  version: {
    version: string;
    status: string;
    effective_from: string;
    body: Record<string, unknown>;
    signature: DiscoverySignature;
  };
}

const SEED_DISCOVERY = JSON.parse(`
[{"kind":"pb","body":{"conformance_suite_ref":"https://standards.cen-cenelec.eu/EN-18222/conformance","description":"EN 18222:2026 REST resource model","grammar_ref":"https://standards.cen-cenelec.eu/EN-18222","identifier":"pb-en18222-rest","media_types":["application/vnd.en18222+json"],"operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"8b1810c64059624ad64e82c772134e41669e8a9e6e8ea2309cb133664fefccc868afcd17b1471753a2f1a6e613f66e1d1bead55883cbb0a9dad8841ab7bed505"}},
{"kind":"pb","body":{"conformance_suite_ref":"https://openstd.samr.gov.cn/GB/T-33993/conformance","description":"GB/T 33993 DPP wrapper envelope","grammar_ref":"https://openstd.samr.gov.cn/GB/T-33993","identifier":"pb-gbt-33993","media_types":["application/vnd.gbt33993+json"],"operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"f4e0cc004fa1a58f0e0c180a46d6cd92c984fe032f6ae63fead56b446a4c208dc3cb1654c20dd8abc67b896e8ba80bf2b2af0f041b4bc0fd39a70af0650b9500"}},
{"kind":"pb","body":{"conformance_suite_ref":"https://www.gs1.org/standards/gs1-digital-link/conformance","description":"GS1 Digital Link URI grammar (v1.2)","grammar_ref":"https://www.gs1.org/standards/gs1-digital-link","identifier":"pb-gs1-digital-link","media_types":["application/gs1dl+json"],"operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"0264949fa5e1259f2e09cde5de0e9a3ca290363df4d68b9589ce460e507ae52c02e65e8b6a67415420705008a595d9479efb3ff18f7649fde9da62f9b850f704"}},
{"kind":"pb","body":{"conformance_suite_ref":"https://unidpp.org/spec/tier-a-binary/conformance","description":"UniDPP Tier-A signed binary pack","grammar_ref":"https://unidpp.org/spec/tier-a-binary","identifier":"pb-tier-a-binary","media_types":["application/vnd.unidpp.tier-a"],"operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"bc8ed7d2e324e0c4a27f3d726248c39d2124d4c9b0af762e996381e9231521c948fc86143b6c2aff53baf84257c2b98de5fefb0acce2ec1d5f08a56d74971f01"}},
{"kind":"pb","body":{"conformance_suite_ref":"https://uncefact.unece.org/untp/conformance","description":"UN Transparency Protocol Verifiable Credential profile","grammar_ref":"https://uncefact.unece.org/untp","identifier":"pb-untp-vc","media_types":["application/vc+json","application/vp+json"],"operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"cd0bb40b9fed46267b121343e81a55222864d63a12c12737286510b80510253e4b2bea5e6df8f0ce8efae5d0ac6ef1e3db9b313b77b1b9f706d8c734b0d2420e"}},
{"kind":"vm","body":{"agility_status":"active","identifier":"vm-fips","master_list_ref":"https://unidpp.org/spec/signatif/master-list","operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"suite":"FIPS 186-4 (ECDSA-P256 + RSA-PSS)","trust_framework":"SIGNATIF","trust_list_endpoint":"https://trust.unidpp.org/fips-list"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"d25b558b8f65b9ab4c02a3817b94c9dd0c819084a1c1f1c44fadab1a2b59f69f5ba645c12ff1cbf0e1d009e7b8c9aae5924713d2a19fda9e178d4e031e3d820f"}},
{"kind":"vm","body":{"agility_status":"migration","identifier":"vm-ml-dsa","master_list_ref":"https://unidpp.org/spec/signatif/master-list","operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"suite":"FIPS 204 ML-DSA-65 (migration phase)","trust_framework":"SIGNATIF","trust_list_endpoint":"https://trust.unidpp.org/pq-list"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"1f9a92b3038e27e671becfd92749ff5a7440fb2390b3b92d69eb04a9c41179a56713f96f20164a84d0967d6e0a3844d8f827b7a3ebceebb27f4312e7f9892307"}},
{"kind":"vm","body":{"agility_status":"active","identifier":"vm-sm2-sm3-sm4","master_list_ref":"https://unidpp.org/spec/signatif/master-list","operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"suite":"SM2-SM3-SM4","trust_framework":"SIGNATIF","trust_list_endpoint":"https://trust.unidpp.org/sm2-list"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"195353a5214a9d42f6e22fde6be8bb90f61f18db38ea05ca72d0242be2ecd449ed1ebd700e2617886a667d2558f4ba120715c1ed003fd99fe239f1d5c373910b"}},
{"kind":"service","identifier":"unidpp-archive-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"archive","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-archive.unidpp.org/"}],"identifier":"unidpp-archive-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-763b38314f0f1189","key_id":"k-100fefc84e442ed0","label":"unidpp-archive","public_key":"23fda9a11d2b3df752a9da23d6d2892b7a39861030bae94db68f5cb7048588e3"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-100fefc84e442ed0","value":"9d83809554cf576824567eb5146fafbebb0387372beba2bf43761f4e0105662f50be579990eb602b9b10610d76e1c6d476397c511f36e2269170936f57070204"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-100fefc84e442ed0","value":"9d83809554cf576824567eb5146fafbebb0387372beba2bf43761f4e0105662f50be579990eb602b9b10610d76e1c6d476397c511f36e2269170936f57070204"}}},
{"kind":"service","identifier":"unidpp-cli-verifier-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"edge","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-cli-verifier.unidpp.org/"}],"identifier":"unidpp-cli-verifier-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-db43284f7ca187ae","key_id":"k-ade6722e1a535a88","label":"unidpp-cli-verifier","public_key":"3d6fa332917ca548ce3556598acced8ef5bba6394169083a64820346c04d7b5d"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-ade6722e1a535a88","value":"083766a368f16a57fe2884422e8dc37b52b506c850755c401576136b8b39c43c30d826b1a86882970382dd1e6ae311a1597141d997700afcec786d8ab5973e08"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-ade6722e1a535a88","value":"083766a368f16a57fe2884422e8dc37b52b506c850755c401576136b8b39c43c30d826b1a86882970382dd1e6ae311a1597141d997700afcec786d8ab5973e08"}}},
{"kind":"service","identifier":"unidpp-edge-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"edge","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-edge.unidpp.org/"}],"identifier":"unidpp-edge-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-9acc2f6d4b5ccbf7","key_id":"k-7bd9d45bba15959d","label":"unidpp-edge","public_key":"51ab78a5a440a4a63a63ff251ebff85be2008f16e1e8f900006b3f4e15705f1e"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-7bd9d45bba15959d","value":"b217127d1d7c7f143b6af9173c128bfe31ab5563b25f04ca1367f512374ea1862bc6f9305ee23aed71083321c22e5c846dd0895c036012256f1b3e39f3fa9c0d"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-7bd9d45bba15959d","value":"b217127d1d7c7f143b6af9173c128bfe31ab5563b25f04ca1367f512374ea1862bc6f9305ee23aed71083321c22e5c846dd0895c036012256f1b3e39f3fa9c0d"}}},
{"kind":"service","identifier":"unidpp-issuer-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"issuer","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-issuer.unidpp.org/"}],"identifier":"unidpp-issuer-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-a63ad18db30ce0ee","key_id":"k-81e117d6abbaf882","label":"unidpp-issuer","public_key":"caf2d5f466cff0b33295ec6a908c8c9fbb7ead79ae8ed2bdead2b056bc9ef6ee"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-81e117d6abbaf882","value":"094b0c5ffbe9bf7431e11a7611e97e62283b4f12b61e31fcc3f0a2bc42555d6f511cca99e2bdf56f8b11c3dbf49babd5bf2863ca6cd0a9853e70cba6899d1904"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-81e117d6abbaf882","value":"094b0c5ffbe9bf7431e11a7611e97e62283b4f12b61e31fcc3f0a2bc42555d6f511cca99e2bdf56f8b11c3dbf49babd5bf2863ca6cd0a9853e70cba6899d1904"}}},
{"kind":"service","identifier":"unidpp-log-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"log","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-log.unidpp.org/"}],"identifier":"unidpp-log-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-11803fba7261afdb","key_id":"k-0f19ae4f9763b4b3","label":"unidpp-log","public_key":"a7602ecbb3b4df24cf5927ca60f7bcb80d0d944b2a73490389e53a63354b6950"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-0f19ae4f9763b4b3","value":"f95df022eafa787cb7a978f687d97c19287a83e5a6dd41bdeac439eb92e82d5ea7e1a35771fdbfb466d486e4e2097332c754553112f6c01ca69e06d7ca25580f"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-0f19ae4f9763b4b3","value":"f95df022eafa787cb7a978f687d97c19287a83e5a6dd41bdeac439eb92e82d5ea7e1a35771fdbfb466d486e4e2097332c754553112f6c01ca69e06d7ca25580f"}}},
{"kind":"service","identifier":"unidpp-registry-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"registry","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-registry.unidpp.org/"}],"identifier":"unidpp-registry-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-aa3344a691621b23","key_id":"k-d4613a88f0255bf5","label":"unidpp-registry","public_key":"e4d8be26792ec0f3086e872caa6df7ec7a6662090ef62035f57cc6ec44752d8f"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"78a92d7c02e57e96fad070e03d38b64d7a63a6bf3854a70fad8565814cd303d16e5a9033fff16ca0111691bf6b53f93370a25837e215e82826bbfa4584749b0b"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-d4613a88f0255bf5","value":"78a92d7c02e57e96fad070e03d38b64d7a63a6bf3854a70fad8565814cd303d16e5a9033fff16ca0111691bf6b53f93370a25837e215e82826bbfa4584749b0b"}}},
{"kind":"service","identifier":"unidpp-resolver-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"resolver","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-resolver.unidpp.org/"}],"identifier":"unidpp-resolver-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-ef8cacff9d262181","key_id":"k-3262ddce2ed4049c","label":"unidpp-resolver","public_key":"bb2ab71a0e230cc061065f72588333cfc6d6f8b21e94cc53e0e5fcc6a703589b"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-3262ddce2ed4049c","value":"b3f1bb9b03e8e8eec3edfbad95de39e588961143db9ce5eed8a08306a64c15efa19c36739d30e364ba09ac4e61a0e53285167a1852fa1a981c6528cdc597f202"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-3262ddce2ed4049c","value":"b3f1bb9b03e8e8eec3edfbad95de39e588961143db9ce5eed8a08306a64c15efa19c36739d30e364ba09ac4e61a0e53285167a1852fa1a981c6528cdc597f202"}}},
{"kind":"service","identifier":"unidpp-trust-v1","version":{"version":"1.0.0","status":"active","effective_from":"2026-09-01T00:00:00Z","body":{"class":"trust","effective_from":"2026-09-01T00:00:00Z","endpoints":[{"protocol_binding_ref":"pb-tier-a-binary","uri":"https://unidpp-trust.unidpp.org/"}],"identifier":"unidpp-trust-v1","jurisdiction":"ZZ","operator":{"algorithm":"ed25519","id":"op-acf68a4e69101785","key_id":"k-a002d132961b316c","label":"unidpp-trust","public_key":"e3c416846e336889c42a30e842078e70009a6a71720f430f09f6f1bfad2efd2e"},"protocol_binding_ref":"pb-tier-a-binary","residency_class":"anywhere","signature":{"algorithm":"ed25519","key_id":"k-a002d132961b316c","value":"26367e75395f287e254db49f652fd59f9a4517f7a57ed9d8a1a204bd6718811727ab7da87378ce6079b35f873af1dddd604455c67732395f543fe56cea9c0e02"},"status":"active","version":"1.0.0"},"signature":{"algorithm":"ed25519","key_id":"k-a002d132961b316c","value":"26367e75395f287e254db49f652fd59f9a4517f7a57ed9d8a1a204bd6718811727ab7da87378ce6079b35f873af1dddd604455c67732395f543fe56cea9c0e02"}}}
]`) as SeedProtocolBinding[] | SeedVerificationMechanism[] | SeedService[];

// The seed units (C1 subregister: SI base + kWh/MJ/J with ISO 80000
// citations) — the native seed's own table.
const SEED_UNITS: [string, string, string][] = [
  ["unit-m", "metre", "ISO 80000-3:2006"],
  ["unit-kg", "kilogram", "ISO 80000-4:2006"],
  ["unit-s", "second", "ISO 80000-3:2006"],
  ["unit-a", "ampere", "ISO 80000-6:2006"],
  ["unit-k", "kelvin", "ISO 80000-5:2007"],
  ["unit-mol", "mole", "ISO 80000-9:2009"],
  ["unit-cd", "candela", "ISO 80000-7:2008"],
  ["unit-kwh", "kilowatt hour", "ISO 80000-4:2006 (energy); 1 kWh = 3.6 MJ exactly"],
  ["unit-mj", "megajoule", "ISO 80000-4:2006 (energy)"],
  ["unit-j", "joule", "ISO 80000-4:2006 (energy)"],
];

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

// The clause-15 tier form of a cross-register mapping (alongside
// the relation form): source, target, version and a tiered kind.
// The tier duties the shape check enforces at intake, per clause
// 15's intake obligation.
const mappingFailure = (path: string, message: string): IntakeFailure => ({
  check: "cross-register-mapping-integrity",
  path,
  message,
});

export function mappingTierErrors(
  manifest: Record<string, unknown>,
  store: RegistryState,
): IntakeFailure[] {
  const splitFailure = (line: string): IntakeFailure => {
    const at = line.indexOf(": ");
    return at > 0
      ? mappingFailure(line.slice(0, at), line.slice(at + 2))
      : mappingFailure("manifest", line);
  };
  const errors: IntakeFailure[] = [];
  const source = typeof manifest["source"] === "string" ? manifest["source"] : "";
  const target = typeof manifest["target"] === "string" ? manifest["target"] : "";
  if (!source) errors.push(splitFailure("manifest.source: the mapping names its source item"));
  if (!target) errors.push(splitFailure("manifest.target: the mapping names its target item"));
  const version = manifest["version"];
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    errors.push(splitFailure("manifest.version: the mapping's own version is a positive integer"));
  }
  const kind = manifest["kind"] as Record<string, unknown> | undefined;
  if (!kind || typeof kind !== "object") {
    errors.push(splitFailure("manifest.kind: the tier form carries its tiered kind"));
    return errors;
  }
  for (const [side, reference] of [
    ["source", source],
    ["target", target],
  ] as const) {
    if (!reference) continue;
    const identifier = reference.split("@")[0];
    if (!store.item(identifier)) {
      errors.push(
        splitFailure(
          `manifest.${side}: dangling reference: no registry item \`${identifier}\` names the ${side} end`,
        ),
      );
    }
  }
  const tier = kind["tier"];
  if (tier === "deterministic") {
    const transform = kind["transform"];
    if (typeof transform !== "string" || !transform.trim()) {
      errors.push(splitFailure("manifest.kind.transform: a tier-1 mapping names its registered, versioned transform"));
    }
  } else if (tier === "correspondence") {
    const scope = kind["scope"];
    if (!Array.isArray(scope) || scope.length === 0) {
      errors.push(splitFailure("manifest.kind.scope: a tier-2 correspondence declares its scope (what it covers)"));
    }
    const residual = kind["residual"];
    if (typeof residual !== "string" || !residual.trim()) {
      errors.push(splitFailure("manifest.kind.residual: a tier-2 correspondence states its residual (what it does not cover)"));
    }
    const attester = kind["attester"];
    if (typeof attester !== "string" || !attester.trim()) {
      errors.push(splitFailure("manifest.kind.attester: a tier-2 correspondence names its attester"));
    }
  } else if (tier === "no-mapping") {
    const note = kind["note"];
    if (typeof note !== "string" || !note.trim()) {
      errors.push(splitFailure("manifest.kind.note: a tier-3 record states why no correspondence is asserted"));
    }
  } else {
    errors.push(splitFailure("manifest.kind.tier: the tier is one of deterministic, correspondence, no-mapping"));
  }
  return errors;
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
// The intake chain's failure record: the native IntakeError's wire
// form — the check that rejected, the manifest path, the verbatim
// message.
export interface IntakeFailure {
  check: string;
  path: string;
  message: string;
}

// The native intake_error_response: the first failing check names the
// refusal, the full list rides beside it.
export function intakeResponse(
  failures: IntakeFailure[],
  asOf: string,
): Response {
  const list = failures.map((f) => ({
    check: f.check,
    path: f.path,
    message: f.message,
  }));
  const first = failures[0];
  const error = first
    ? `${first.check} rejected the item: ${first.message}`
    : "intake validation failed";
  return stamped(400, { error, errors: list }, asOf);
}

const signatureFailure = (
  path: string,
  message: string,
): IntakeFailure => ({
  check: "class-descriptor-signature-required",
  path,
  message,
});

export function descriptorSignatureErrors(
  manifest: Record<string, unknown> | undefined,
): IntakeFailure[] {
  if (!manifest) {
    return [
      signatureFailure(
        "manifest",
        "a class descriptor registers its SIGNED manifest (issuer_class, issuer, signature) — no manifest given",
      ),
    ];
  }
  const failures: IntakeFailure[] = [];
  const issuerClass = manifest["issuer_class"];
  if (typeof issuerClass !== "string" || !issuerClass.trim()) {
    failures.push(
      signatureFailure(
        "manifest.issuer_class",
        "class descriptors are signed by their issuer: the manifest must state its issuer_class (law | treaty | consensus | declaration | attestation)",
      ),
    );
  } else if (!ISSUER_CLASSES.includes(issuerClass)) {
    failures.push(
      signatureFailure(
        "manifest.issuer_class",
        `\`${issuerClass}\` is not an issuer class (one of ${ISSUER_CLASSES.join(", ")})`,
      ),
    );
  }
  const issuer = manifest["issuer"];
  if (typeof issuer !== "string" || !issuer.trim()) {
    failures.push(
      signatureFailure("manifest.issuer", "the issuing node's id is required (the signer of record)"),
    );
  }
  const signature = (manifest["signature"] as Record<string, unknown> | undefined)?.["signature"];
  if (typeof signature !== "string" || !signature.trim()) {
    failures.push(
      signatureFailure(
        "manifest.signature",
        "class descriptors register only in their SIGNED form: a signature slot with a signature value is required (the cryptographic reading is the trust service's)",
      ),
    );
  }
  return failures;
}

const profileSignatureFailure = (path: string, message: string): IntakeFailure => ({
  check: "profile-signature-required",
  path,
  message,
});

// The profile's signed form (the chain's first profile check): the
// issuer class, the issuing node, the signature slot filled.
export function profileSignatureErrors(
  manifest: Record<string, unknown> | undefined,
): IntakeFailure[] {
  if (!manifest) {
    return [
      profileSignatureFailure(
        "manifest",
        "a profile item registers its SIGNED manifest (issuer_class, issuer, signature) — no manifest given",
      ),
    ];
  }
  const failures: IntakeFailure[] = [];
  const issuerClass = manifest["issuer_class"];
  if (typeof issuerClass !== "string" || !issuerClass.trim()) {
    failures.push(
      profileSignatureFailure(
        "manifest.issuer_class",
        "profiles are signed by their issuer: the manifest must state its issuer_class (law | treaty | consensus | declaration | attestation)",
      ),
    );
  } else if (!ISSUER_CLASSES.includes(issuerClass)) {
    failures.push(
      profileSignatureFailure(
        "manifest.issuer_class",
        `\`${issuerClass}\` is not an issuer class (one of ${ISSUER_CLASSES.join(", ")})`,
      ),
    );
  }
  const issuer = manifest["issuer"];
  if (typeof issuer !== "string" || !issuer.trim()) {
    failures.push(
      profileSignatureFailure("manifest.issuer", "the issuing node's id is required (the signer of record)"),
    );
  }
  const signature = (manifest["signature"] as Record<string, unknown> | undefined)?.["signature"];
  if (typeof signature !== "string" || !signature.trim()) {
    failures.push(
      profileSignatureFailure(
        "manifest.signature",
        "profiles register only in their SIGNED form: a signature slot with a signature value is required (the cryptographic reading is the trust service's)",
      ),
    );
  }
  return failures;
}

const manifestFailure = (path: string, message: string): IntakeFailure => ({
  check: "class-descriptor-manifest",
  path,
  message,
});

export function descriptorManifestErrors(
  identifier: string,
  manifest: Record<string, unknown>,
): IntakeFailure[] {
  const failures: IntakeFailure[] = [];
  const classId = manifest["class_id"];
  if (typeof classId !== "string" || !classId) {
    failures.push(
      manifestFailure("manifest.class_id", "the descriptor states its class_id (the identifier names the class)"),
    );
  } else if (classId !== identifier) {
    failures.push(
      manifestFailure(
        "manifest.class_id",
        `the descriptor's class_id \`${classId}\` must name the item itself (\`${identifier}\`): the identifier IS the class`,
      ),
    );
  }
  const parsed = parseFeatureSpecs(manifest);
  if (!parsed.ok) {
    failures.push(
      ...parsed.errors.map((line) => {
        const at = line.indexOf(": ");
        return at > 0
          ? manifestFailure(line.slice(0, at), line.slice(at + 2))
          : manifestFailure("manifest.features", line);
      }),
    );
  } else if (parsed.specs.length === 0) {
    failures.push(
      manifestFailure("manifest.features", "a class descriptor declares at least one feature"),
    );
  }
  const capabilityClasses = manifest["capability_classes"];
  if (!Array.isArray(capabilityClasses)) {
    failures.push(
      manifestFailure(
        "manifest.capability_classes",
        "the descriptor states the capability classes that may carry it",
      ),
    );
  } else if (capabilityClasses.length === 0) {
    failures.push(
      manifestFailure(
        "manifest.capability_classes",
        "the descriptor states at least one capability class (S0–S3)",
      ),
    );
  } else {
    capabilityClasses.forEach((token, index) => {
      if (typeof token !== "string" || !CAPABILITY_CLASSES.includes(token)) {
        failures.push(
          manifestFailure(
            `manifest.capability_classes[${index}]`,
            `\`${String(token)}\` is not a capability class (one of ${CAPABILITY_CLASSES.join(", ")})`,
          ),
        );
      }
    });
  }
  // The rule references' deterministic reading (G4): every reference
  // resolves to a declared rule, and each expression parses and reads
  // only declared features with compatible kinds. Rules absent or
  // not an array declare none (the native reads them as absent).
  const declaredRules = new Map<string, string>();
  const rules = manifest["rules"];
  if (Array.isArray(rules)) {
    rules.forEach((rule, index) => {
      const record = rule as Record<string, unknown>;
      const id = typeof record["id"] === "string" ? record["id"].trim() : "";
      const expression = typeof record["expr"] === "string" ? record["expr"] : "";
      if (!id) {
        failures.push(manifestFailure(`manifest.rules[${index}].id`, "a rule states its id"));
        return;
      }
      if (declaredRules.has(id)) {
        failures.push(
          manifestFailure(`manifest.rules[${index}].id`, `the rule id \`${id}\` is declared twice`),
        );
      }
      declaredRules.set(id, expression);
      const parsed = parseRule(expression);
      if (!parsed.ok) {
        failures.push(
          manifestFailure(
            `manifest.rules[${index}].expr`,
            `the expression does not parse: at offset ${parsed.error.offset}, ${parsed.error.message}`,
          ),
        );
        return;
      }
      const kinds = new Map<string, string>();
      const specs = parseFeatureSpecs(manifest);
      if (specs.ok) {
        for (const spec of specs.specs) kinds.set(spec.path, spec.kind);
      }
      for (const message of ruleDescriptorErrors(parsed.expr, kinds)) {
        failures.push(manifestFailure(`manifest.rules[${index}].expr`, message));
      }
    });
  }
  const ruleReferences = manifest["rule_references"];
  if (!Array.isArray(ruleReferences)) {
    failures.push(
      manifestFailure(
        "manifest.rule_references",
        "the descriptor states the rule references it relies on (an empty array declares none)",
      ),
    );
  } else {
    ruleReferences.forEach((token, index) => {
      if (typeof token !== "string" || !token.trim()) {
        failures.push(
          manifestFailure(`manifest.rule_references[${index}]`, "a rule reference is a non-empty rule id"),
        );
        return;
      }
      if (!declaredRules.has(token)) {
        failures.push(
          manifestFailure(
            `manifest.rule_references[${index}]`,
            `the rule reference \`${token}\` names no rule the descriptor declares in \`rules\``,
          ),
        );
      }
    });
  }
  return failures;
}

export function instanceErrors(
  manifest: Record<string, unknown> | undefined,
  store: RegistryState,
): IntakeFailure[] {
  if (!manifest) {
    return [
      instanceFailure("manifest", "an instance carries a manifest (instance_of, features)"),
    ];
  }
  const classId = typeof manifest["instance_of"] === "string" ? manifest["instance_of"].trim() : "";
  if (!classId) {
    return [
      instanceFailure(
        "manifest.instance_of",
        "the instance states the class it instantiates (the descriptor's identifier)",
      ),
    ];
  }
  const descriptor = store.item(classId);
  if (!descriptor) {
    return [
      instanceFailure(
        "manifest.instance_of",
        `unknown class \`${classId}\`: no registered class descriptor names it`,
      ),
    ];
  }
  if (descriptor.item_class !== "class-descriptor") {
    return [
      instanceFailure(
        "manifest.instance_of",
        `\`${classId}\` is registered as a ${descriptor.item_class}, not a class descriptor`,
      ),
    ];
  }
  if (!descriptor.manifest) {
    return [
      instanceFailure(
        "manifest.instance_of",
        `the class descriptor \`${classId}\` carries no manifest`,
      ),
    ];
  }
  const parsed = parseFeatureSpecs(descriptor.manifest);
  if (!parsed.ok) {
    return parsed.errors.map((line) => {
      const at = line.indexOf(": ");
      const [path, message] = at > 0 ? [line.slice(0, at), line.slice(at + 2)] : ["", line];
      return instanceFailure(
        `manifest.instance_of (${path})`,
        `the class descriptor \`${classId}\` itself does not parse: ${message}`,
      );
    });
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
  const failures = instanceAgainstSpecs(classId, parsed.specs, features, store);
  for (const reference of (descriptor.manifest["rule_references"] as string[] | undefined) ?? []) {
    const expression = declaredRules.get(reference);
    if (!expression) continue; // the descriptor intake refuses dangling references
    const parsed = parseRule(expression);
    if (parsed.ok && !evalRule(parsed.expr, features)) {
      failures.push(
        instanceFailure(
          `manifest.rule_references.${reference}`,
          `the rule \`${reference}\` of the class \`${classId}\` is not satisfied: ${expression}`,
        ),
      );
    }
  }
  return failures;
}

const instanceFailure = (path: string, message: string): IntakeFailure => ({
  check: "instance-against-class",
  path,
  message,
});

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
): IntakeFailure[] {
  const failures: IntakeFailure[] = [];
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
        failures.push(
          instanceFailure(
            `manifest.features.${spec.path}`,
            `the class \`${classId}\` declares \`${spec.path}\` required; the instance states no fact at that path (missing-required)`,
          ),
        );
      }
      continue;
    }
    const presented = valueKind(fact);
    if (presented !== spec.kind) {
      failures.push(
        instanceFailure(
          `manifest.features.${spec.path}`,
          `the fact at \`${spec.path}\` presents as ${presented ?? "neither string, decimal, boolean nor a list of strings"}; the class \`${classId}\` declares \`${spec.kind}\` (wrong-kind)`,
        ),
      );
      continue;
    }
    if (spec.vocabulary) {
      const member = fact as string;
      if (!spec.vocabulary.includes(member)) {
        failures.push(
          instanceFailure(
            `manifest.features.${spec.path}`,
            `\`${member}\` is outside the vocabulary the class \`${classId}\` declares for \`${spec.path}\` (out-of-vocabulary; members: ${spec.vocabulary.join(", ")})`,
          ),
        );
      }
    }
  }
  for (const spec of specs) {
    if (!spec.unit || !checkUnits) continue;
    const unitItem = store.item(spec.unit);
    if (!unitItem) {
      failures.push(
        instanceFailure(
          `manifest.features.${spec.path}`,
          `the class \`${classId}\` declares unit \`${spec.unit}\` for \`${spec.path}\`, but no registered unit names it (unresolved-unit)`,
        ),
      );
    } else if (unitItem.item_class !== "unit") {
      failures.push(
        instanceFailure(
          `manifest.features.${spec.path}`,
          `the class \`${classId}\` declares unit \`${spec.unit}\` for \`${spec.path}\`, but that identifier registers as a ${unitItem.item_class} (unresolved-unit)`,
        ),
      );
    }
  }
  return failures;
}

// The class descriptor's machine-checkable form in the discovery
// documents (R10 G6): a verifier meeting an unknown CLASS resolves
// the class's own descriptor here.
function classDescriptorJson(descriptor: Item): Record<string, unknown> {
  const parsed = descriptor.manifest ? parseFeatureSpecs(descriptor.manifest) : null;
  const specs = parsed && parsed.ok ? parsed.specs : [];
  return {
    class_id: descriptor.identifier,
    title: descriptor.title,
    register: descriptor.register,
    features: specs.map((f) => ({
      path: f.path,
      kind: f.kind,
      required: f.required,
      vocabulary: f.vocabulary ?? null,
      unit: f.unit ?? null,
    })),
    subregister: "/class-descriptors",
  };
}

// The subregister mounts (the native root document's `subregisters`).
function subregistersJson(): Record<string, Record<string, string>> {
  return Object.fromEntries(
    ITEM_CLASSES.map((c) => [
      CLASS_PLURALS[c] ?? c,
      { class: c, path: `/${CLASS_PLURALS[c] ?? c}` },
    ]),
  );
}

// The stamp an audit record carries: the journal writes it on the new
// ops; the register-item / supersede-version ops ride theirs inside
// the stored versions.
function auditRecordedAt(op: JournalOp): string {
  const carried = op["recorded_at"];
  if (typeof carried === "string") return carried;
  if (op.op === "register-item") {
    const item = op["item"] as Item | undefined;
    const registered = item?.versions[item.versions.length - 1]?.registered_at;
    if (registered) return registered;
  }
  if (op.op === "supersede-version") {
    const registered = (op["successor"] as ItemVersion | undefined)?.registered_at;
    if (registered) return registered;
  }
  return isoNow();
}

// One audit record's wire form (the native `AuditRecord::to_json`):
// the op with its payload, then the journal sequence and the stamp.
function auditRecordJson(op: JournalOp, seq: number): Record<string, unknown> {
  const record: Record<string, unknown> = { op: op.op };
  switch (op.op) {
    case "register-item":
      record["item"] = itemJson(op["item"] as Item);
      break;
    case "supersede-version": {
      record["identifier"] = op["identifier"];
      record["superseded_version"] = op["superseded_version"];
      record["prior_status"] = op["prior_status"];
      record["successor"] = plainVersionJson(op["successor"] as ItemVersion);
      if (op["manifest"] !== undefined) record["manifest"] = op["manifest"];
      break;
    }
    case "bind-applicability":
      record["binding"] = bindingJson(op["binding"] as ApplicabilityBinding);
      break;
    case "register-service":
      record["descriptor"] = serviceDescriptorJournalJson(
        op["descriptor"] as ServiceDescriptorRec,
      );
      break;
    case "supersede-service":
      record["identifier"] = op["identifier"];
      record["superseded_version"] = op["superseded_version"];
      record["prior_status"] = op["prior_status"];
      record["successor"] = serviceVersionJson(
        op["successor"] as ServiceVersionRec,
        null,
      );
      break;
    case "register-protocol-binding":
      record["binding"] = protocolBindingJson(op["binding"] as ProtocolBindingRec);
      break;
    case "register-verification-mechanism":
      record["mechanism"] = verificationMechanismJson(
        op["mechanism"] as VerificationMechanismRec,
      );
      break;
    case "update-model-validation": {
      record["identifier"] = op["identifier"];
      record["version"] = op["version"];
      record["status"] = op["status"];
      record["tool"] = op["tool"];
      if (op["detail"] !== undefined) record["detail"] = op["detail"];
      break;
    }
    default:
      // An unknown op rides verbatim (minus the op discriminator).
      for (const [key, value] of Object.entries(op)) {
        if (key !== "op") record[key] = value;
      }
      break;
  }
  record["seq"] = seq;
  record["recorded_at"] = auditRecordedAt(op);
  return record;
}

export const STATUSES = ["valid", "superseded", "retired"];

const tokenOk = (value: string): boolean =>
  value.length > 0 && value.length <= 256 && !value.includes("/") && !/\s/.test(value);

// The trimmed, non-empty query parameter (the native `opt_query`).
const optQuery = (params: URLSearchParams, key: string): string | null => {
  const value = params.get(key)?.trim();
  return value ? value : null;
};

// The non-empty-string body field (the native `opt_str`): absent or
// null is absent, a non-empty string is its trimmed value, anything
// else is a refusal.
function optNonEmptyString(v: Record<string, unknown>, key: string): string | null {
  const value = v[key];
  if (value === undefined || value === null) return null;
  if (typeof value === "string" && value.trim() !== "") return value.trim();
  throw new Error(`\`${key}\` must be a non-empty string`);
}

// The loose body string (the native's product_type/subject read):
// only a non-empty string names the subject.
const optBodyString = (v: Record<string, unknown>, key: string): string | null => {
  const value = v[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
};

function optTimestamp(v: Record<string, unknown>, key: string): Date | null {
  const value = v[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new Error(`\`${key}\` must be an RFC 3339 string`);
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) {
    throw new Error(
      `\`${key}\`: invalid timestamp \`${value}\` (expected RFC 3339 UTC)`,
    );
  }
  return at;
}

// The validation status a model's deposit manifest carries (the
// native `model_validation_status` — pending when the manifest
// carries no readable deposit).
const modelValidationStatus = (item: Item): string => {
  const validation = (
    item.manifest?.["express"] as Record<string, unknown> | undefined
  )?.["validation"] as Record<string, unknown> | undefined;
  const status = validation?.["status"];
  return typeof status === "string" ? status : "pending";
};

// The binding's legal as-of semantics (the native `applies_at`): a
// retroactive binding applies from its `effective_from`; a
// non-retroactive one only from its `registered_at`.
function bindingAppliesAt(binding: ApplicabilityBinding, t: Date): boolean {
  if (binding.effective_from && t < new Date(binding.effective_from)) return false;
  if (binding.effective_until && t >= new Date(binding.effective_until)) return false;
  if (!binding.retroactive && binding.registered_at && t < new Date(binding.registered_at)) {
    return false;
  }
  return true;
}

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

const conflict = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 409,
    headers: { "content-type": "application/json" },
  });

const stamped = (status: number, body: unknown, asOf: string): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-as-of": asOf },
  });

const stampedWith = (
  status: number,
  body: unknown,
  contentType: string,
  asOf: string,
): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": contentType, "x-as-of": asOf },
  });

// One version's plain wire form (the Rust `to_json` without the
// derived window).
export function plainVersionJson(candidate: ItemVersion): Record<string, unknown> {
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
  return view;
}

// Resolved effective window end (the Rust `Item::window_until`):
// explicit `effective_until`, else the successor's `effective_from`,
// else open.
function windowUntil(item: Item, candidate: ItemVersion): string | null {
  if (candidate.effective_until) return candidate.effective_until;
  if (!candidate.superseded_by_version) return null;
  const successor = item.versions.find(
    (v) => v.version === candidate.superseded_by_version,
  );
  return successor?.effective_from ?? null;
}

// One version's own view (the Rust `ItemVersion::to_json`).
export function renderVersion(item: Item, candidate: ItemVersion): Record<string, unknown> {
  const view = plainVersionJson(candidate);
  // The successor's effective_from closes this window.
  const windowEnd = windowUntil(item, candidate);
  if (windowEnd) view.window_end = windowEnd;
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

// ---------------------------------------------------------------------------
// Discovery wire forms (the native discovery.rs renders): the C3
// service versions carry their ordered history and the resolved
// window ends; the C4/C5 records are their bodies with the canonical
// fields and the signature block stated.
// ---------------------------------------------------------------------------

const signatureJson = (signature: DiscoverySignature): Record<string, unknown> => ({
  key_id: signature.key_id,
  algorithm: signature.algorithm,
  value: signature.value,
});

function serviceVersionJson(
  version: ServiceVersionRec,
  windowEnd: string | null,
): Record<string, unknown> {
  const view: Record<string, unknown> = {
    version: version.version,
    status: version.status,
    effective_from: version.effective_from,
  };
  if (version.effective_until) view.effective_until = version.effective_until;
  view.registered_at = version.registered_at;
  if (version.superseded_by_version)
    view.superseded_by_version = version.superseded_by_version;
  view.body = version.body;
  view.signature = signatureJson(version.signature);
  if (windowEnd) view.window_end = windowEnd;
  return view;
}

// Versions ordered by (effective_from, version) — Ruby parity.
function orderedServiceVersions(descriptor: ServiceDescriptorRec): ServiceVersionRec[] {
  return [...descriptor.versions].sort(
    (a, b) =>
      a.effective_from.localeCompare(b.effective_from) ||
      a.version.localeCompare(b.version),
  );
}

function serviceWindowUntil(
  descriptor: ServiceDescriptorRec,
  version: ServiceVersionRec,
): string | null {
  if (version.effective_until) return version.effective_until;
  if (!version.superseded_by_version) return null;
  const successor = descriptor.versions.find(
    (v) => v.version === version.superseded_by_version,
  );
  return successor?.effective_from ?? null;
}

// The current version: latest active, else any non-superseded.
function currentServiceVersion(descriptor: ServiceDescriptorRec): ServiceVersionRec | undefined {
  const ordered = orderedServiceVersions(descriptor);
  const reversed = [...ordered].reverse();
  return (
    reversed.find((v) => v.status === "active") ??
    reversed.find((v) => v.status !== "superseded")
  );
}

// The version in force at `t` (half-open window [from, until)).
function serviceInForceAt(
  descriptor: ServiceDescriptorRec,
  at: Date,
): ServiceVersionRec | undefined {
  return [...orderedServiceVersions(descriptor)]
    .reverse()
    .find((v) => {
      if (at < new Date(v.effective_from)) return false;
      if (v.effective_until && at >= new Date(v.effective_until)) return false;
      return true;
    });
}

function serviceDescriptorJson(
  descriptor: ServiceDescriptorRec,
  asOf: string,
  at: Date | null,
): Record<string, unknown> {
  const resolved = at
    ? serviceInForceAt(descriptor, at)
    : currentServiceVersion(descriptor);
  return {
    identifier: descriptor.identifier,
    kind: "service",
    versions: orderedServiceVersions(descriptor).map((v) =>
      serviceVersionJson(v, serviceWindowUntil(descriptor, v)),
    ),
    version: resolved ? serviceVersionJson(resolved, serviceWindowUntil(descriptor, resolved)) : null,
    as_of: asOf,
  };
}

// The journal storage form (no `as_of`; the record replays to the
// stamps it carries).
function serviceDescriptorJournalJson(
  descriptor: ServiceDescriptorRec,
): Record<string, unknown> {
  return {
    identifier: descriptor.identifier,
    versions: orderedServiceVersions(descriptor).map((v) =>
      serviceVersionJson(v, null),
    ),
  };
}

function protocolBindingJson(rec: ProtocolBindingRec): Record<string, unknown> {
  const view: Record<string, unknown> = { ...rec.body };
  view.identifier = rec.identifier;
  view.version = rec.version;
  view.grammar_ref = rec.grammar_ref;
  view.media_types = rec.media_types;
  if (rec.conformance_suite_ref) view.conformance_suite_ref = rec.conformance_suite_ref;
  view.signature = signatureJson(rec.signature);
  return view;
}

function verificationMechanismJson(rec: VerificationMechanismRec): Record<string, unknown> {
  const view: Record<string, unknown> = { ...rec.body };
  view.identifier = rec.identifier;
  view.suite = rec.suite;
  view.agility_status = rec.agility_status;
  if (rec.trust_framework) view.trust_framework = rec.trust_framework;
  if (rec.trust_list_endpoint) view.trust_list_endpoint = rec.trust_list_endpoint;
  if (rec.master_list_ref) view.master_list_ref = rec.master_list_ref;
  if (rec.verdict_grammar_ref) view.verdict_grammar_ref = rec.verdict_grammar_ref;
  view.signature = signatureJson(rec.signature);
  return view;
}

function bindingJson(binding: ApplicabilityBinding): Record<string, unknown> {
  const view: Record<string, unknown> = {
    id: binding.id,
    subject: binding.subject,
    profile_item: binding.profile_item,
  };
  if (binding.register) view.register = binding.register;
  if (binding.profile_version) view.profile_version = binding.profile_version;
  if (binding.effective_from) view.effective_from = binding.effective_from;
  if (binding.effective_until) view.effective_until = binding.effective_until;
  if (binding.registered_at) view.registered_at = binding.registered_at;
  view.retroactive = binding.retroactive;
  return view;
}

// Follows supersession links from the earliest version (or from
// `from`, when given) to the terminal version; errors on unknown
// start versions and broken/cyclic links (the native texts).
function itemSupersessionChain(item: Item, from: string | null): ItemVersion[] {
  const start = from
    ? item.versions.find((v) => v.version === from)
    : item.versions[0];
  if (!start) {
    throw new Error(from ? `item \`${item.identifier}\` has no version \`${from}\`` : `item \`${item.identifier}\` has no versions`);
  }
  const chain: ItemVersion[] = [start];
  for (;;) {
    const next = chain[chain.length - 1].superseded_by_version;
    if (!next) break;
    const successor = item.versions.find((v) => v.version === next);
    if (!successor) {
      throw new Error(
        `item \`${item.identifier}\` has no version \`${next}\` (broken supersession link)`,
      );
    }
    if (chain.some((v) => v.version === successor.version)) {
      throw new Error(
        `supersession cycle at version \`${successor.version}\` of item \`${item.identifier}\``,
      );
    }
    chain.push(successor);
  }
  return chain;
}

// The same chain over a service descriptor's versions.
function serviceSupersessionChain(
  descriptor: ServiceDescriptorRec,
  from: string | null,
): ServiceVersionRec[] {
  const start = from
    ? descriptor.versions.find((v) => v.version === from)
    : orderedServiceVersions(descriptor)[0];
  if (!start) {
    throw new Error(from ? `service \`${descriptor.identifier}\` has no version \`${from}\`` : `service \`${descriptor.identifier}\` has no versions`);
  }
  const chain: ServiceVersionRec[] = [start];
  for (;;) {
    const next = chain[chain.length - 1].superseded_by_version;
    if (!next) break;
    const successor = descriptor.versions.find((v) => v.version === next);
    if (!successor) {
      throw new Error(
        `service \`${descriptor.identifier}\` has no version \`${next}\` (broken supersession link)`,
      );
    }
    if (chain.some((v) => v.version === successor.version)) {
      throw new Error(
        `supersession cycle at version \`${successor.version}\` of service \`${descriptor.identifier}\``,
      );
    }
    chain.push(successor);
  }
  return chain;
}

// The directional lookup over a mapping's relation form: `item`
// matches either end; `source`/`target` match the named end (the
// clause-15 tier form names its ends as strings and matches none).
function mappingMatchesQuery(
  item: Item,
  lookupItem: string | null,
  source: string | null,
  target: string | null,
): boolean {
  const manifest = item.manifest;
  if (!manifest) return false;
  const sideItem = (side: string): string | undefined => {
    const sideValue = manifest[side];
    if (!sideValue || typeof sideValue !== "object") return undefined;
    const named = (sideValue as Record<string, unknown>)["item"];
    return typeof named === "string" ? named : undefined;
  };
  if (lookupItem && sideItem("source") !== lookupItem && sideItem("target") !== lookupItem) {
    return false;
  }
  if (source && sideItem("source") !== source) return false;
  if (target && sideItem("target") !== target) return false;
  return true;
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

// The register's state: the journal's ops replayed in order.
export class RegistryState {
  private items = new Map<string, Item>();
  private services = new Map<string, ServiceDescriptorRec>();
  private protocolBindings = new Map<string, ProtocolBindingRec>();
  private verificationMechanisms = new Map<string, VerificationMechanismRec>();
  private bindings: ApplicabilityBinding[] = [];
  private nextBindingId = 1;
  private seq = 0;
  private loaded = false;
  // The replayed ops in append order — the audit log's records (the
  // sequence numbers are the journal positions).
  private replay: JournalOp[] = [];

  constructor(private readonly journal: Journal) {}

  async load(): Promise<void> {
    if (this.loaded) return;
    for (const op of await this.journal.all()) {
      this.apply(op);
      this.seq += 1;
      this.replay.push(op);
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
    } else if (op.op === "bind-applicability") {
      const binding = op.binding as ApplicabilityBinding;
      this.bindings.push(binding);
      this.nextBindingId = Math.max(this.nextBindingId, binding.id + 1);
    } else if (op.op === "register-service") {
      const descriptor = op.descriptor as ServiceDescriptorRec;
      this.services.set(descriptor.identifier, descriptor);
    } else if (op.op === "supersede-service") {
      const descriptor = this.services.get(op.identifier as string);
      if (!descriptor) return;
      const superseded = descriptor.versions.find(
        (v) => v.version === op.superseded_version,
      );
      const successor = op.successor as ServiceVersionRec;
      if (superseded && superseded.status === "active") superseded.status = "superseded";
      if (superseded) superseded.superseded_by_version = successor.version;
      if (!descriptor.versions.some((v) => v.version === successor.version)) {
        descriptor.versions.push(successor);
      }
    } else if (op.op === "register-protocol-binding") {
      const binding = op.binding as ProtocolBindingRec;
      this.protocolBindings.set(binding.identifier, binding);
    } else if (op.op === "register-verification-mechanism") {
      const mechanism = op.mechanism as VerificationMechanismRec;
      this.verificationMechanisms.set(mechanism.identifier, mechanism);
    } else if (op.op === "update-model-validation") {
      const item = this.items.get(op.identifier as string);
      const express = item?.manifest?.["express"] as
        | Record<string, unknown>
        | undefined;
      if (!express) return;
      const validation: Record<string, unknown> = {
        status: op.status,
        tool: op.tool,
      };
      if (op.detail !== undefined) validation["detail"] = op.detail;
      express["validation"] = validation;
    }
  }

  async registerItem(item: Item): Promise<number> {
    const seq = await this.journal.append({ op: "register-item", item });
    this.seq = seq;
    const op: JournalOp = { op: "register-item", item };
    this.apply(op);
    this.replay.push(op);
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
      successor_version: successor.version,
      successor,
      manifest: manifest ?? undefined,
    } satisfies JournalOp);
    this.seq = seq;
    const op: JournalOp = {
      op: "supersede-version",
      identifier,
      superseded_version: supersededVersion,
      prior_status: prior.status,
      successor_version: successor.version,
      successor,
      manifest: manifest ?? undefined,
    };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async bind(binding: ApplicabilityBinding): Promise<number> {
    const assigned = { ...binding, id: this.nextBindingId };
    this.nextBindingId += 1;
    const seq = await this.journal.append({
      op: "bind-applicability",
      binding: assigned,
      recorded_at: isoNow(),
    });
    this.seq = seq;
    const op: JournalOp = { op: "bind-applicability", binding: assigned };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async registerService(descriptor: ServiceDescriptorRec): Promise<number> {
    const seq = await this.journal.append({
      op: "register-service",
      descriptor,
      recorded_at: isoNow(),
    });
    this.seq = seq;
    const op: JournalOp = { op: "register-service", descriptor };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async supersedeService(
    identifier: string,
    supersededVersion: string,
    successor: ServiceVersionRec,
  ): Promise<number> {
    const descriptor = this.services.get(identifier)!;
    const prior = descriptor.versions.find((v) => v.version === supersededVersion)!;
    const seq = await this.journal.append({
      op: "supersede-service",
      identifier,
      superseded_version: supersededVersion,
      prior_status: prior.status,
      successor,
      recorded_at: isoNow(),
    });
    this.seq = seq;
    const op: JournalOp = {
      op: "supersede-service",
      identifier,
      superseded_version: supersededVersion,
      prior_status: prior.status,
      successor,
    };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async registerProtocolBinding(binding: ProtocolBindingRec): Promise<number> {
    const seq = await this.journal.append({
      op: "register-protocol-binding",
      binding,
      recorded_at: isoNow(),
    });
    this.seq = seq;
    const op: JournalOp = { op: "register-protocol-binding", binding };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async registerVerificationMechanism(mechanism: VerificationMechanismRec): Promise<number> {
    const seq = await this.journal.append({
      op: "register-verification-mechanism",
      mechanism,
      recorded_at: isoNow(),
    });
    this.seq = seq;
    const op: JournalOp = { op: "register-verification-mechanism", mechanism };
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  async updateModelValidation(
    identifier: string,
    version: string,
    validation: { status: string; tool: string; detail?: string },
  ): Promise<number> {
    const op: JournalOp = {
      op: "update-model-validation",
      identifier,
      version,
      status: validation.status,
      tool: validation.tool,
      recorded_at: isoNow(),
    };
    if (validation.detail !== undefined) op["detail"] = validation.detail;
    const seq = await this.journal.append(op);
    this.seq = seq;
    this.apply(op);
    this.replay.push(op);
    return seq;
  }

  item(identifier: string): Item | undefined {
    return this.items.get(identifier);
  }

  allItems(): Item[] {
    return [...this.items.values()];
  }

  service(identifier: string): ServiceDescriptorRec | undefined {
    return this.services.get(identifier);
  }

  // The discovery listings sort by identifier (the native's reads).
  allServices(): ServiceDescriptorRec[] {
    return [...this.services.values()].sort((a, b) =>
      a.identifier.localeCompare(b.identifier),
    );
  }

  protocolBinding(identifier: string): ProtocolBindingRec | undefined {
    return this.protocolBindings.get(identifier);
  }

  allProtocolBindings(): ProtocolBindingRec[] {
    return [...this.protocolBindings.values()].sort((a, b) =>
      a.identifier.localeCompare(b.identifier),
    );
  }

  verificationMechanism(identifier: string): VerificationMechanismRec | undefined {
    return this.verificationMechanisms.get(identifier);
  }

  allVerificationMechanisms(): VerificationMechanismRec[] {
    return [...this.verificationMechanisms.values()].sort((a, b) =>
      a.identifier.localeCompare(b.identifier),
    );
  }

  bindingsFor(subject: string): ApplicabilityBinding[] {
    return this.bindings.filter((b) => b.subject === subject);
  }

  // The journal window for the audit view.
  journalOps(): JournalOp[] {
    return this.replay;
  }
}

export class RegistryDO {
  state: RegistryState;
  // The seed flag rides this DO instance (the native's rides its
  // process): one dataset per instance, idempotent against a replayed
  // journal — records already present are skipped, not duplicated.
  private seeded = false;

  constructor(stateOrStorage: unknown) {
    // workerd hands the DurableObjectState; the tests hand a storage
    // stand-in. The SQL API lives on state.storage.
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    const sql = (source as { sql?: unknown }).sql;
    const journal: Journal = sql
      ? new SqlJournal(source as { sql: unknown })
      : new MapJournal(source as { put(key: string, value: unknown): Promise<void>; get(key: string): Promise<unknown>; list(options: { prefix: string }): Promise<Map<string, unknown>> });
    this.state = new RegistryState(journal);
  }

  async fetch(request: Request): Promise<Response> {
    await this.state.load();
    const url = new URL(request.url);
    const path = url.pathname;
    // The module root: the discovery document (the endpoint
    // references, the vocabularies, the subregister mounts, the
    // as-of and negotiation statements, the intake chain, and the
    // registered class descriptors).
    if (path === "/" && request.method === "GET") return this.discoveryRoot();
    if (path === "/discovery" && request.method === "GET") {
      const descriptors = this.state
        .allItems()
        .filter((i) => i.item_class === "class-descriptor")
        .map(classDescriptorJson);
      return stamped(200, {
        service: "unidpp-registry",
        class_descriptors: descriptors,
        subregisters: subregistersJson(),
        as_of: isoNow(),
      }, isoNow());
    }
    if (path === "/healthz") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "content-type": "application/json" },
      });
    }
    // The audit log and the seed (admin).
    if (path === "/admin/log" && request.method === "GET") return this.adminLog(url);
    if (path === "/admin/seed" && request.method === "POST") return this.adminSeed();
    // The generated profile-manifest schema (item 51).
    if (path === "/schemas/profile-manifest" && request.method === "GET") {
      return this.profileManifestSchema(url);
    }
    // The items surface (existing) plus the supersession chain.
    if (path === "/items" && request.method === "GET") return this.list(url);
    if (path === "/items" && request.method === "POST") return this.create(request);
    const supersede = path.match(/^\/items\/([^/]+)\/versions$/);
    if (supersede && request.method === "POST") {
      return this.supersede(request, decodeURIComponent(supersede[1]), url);
    }
    const itemChain = path.match(/^\/items\/([^/]+)\/supersession$/);
    if (itemChain && request.method === "GET") {
      return this.itemChainRoute(url, decodeURIComponent(itemChain[1]));
    }
    const one = path.match(/^\/items\/([^/]+)$/);
    if (one && request.method === "GET") return this.getOne(url, decodeURIComponent(one[1]));
    // The applicability surface (the bindings + the clock-predicate
    // evaluation).
    if (path === "/applicability" && request.method === "GET") {
      return this.applicabilityQuery(url);
    }
    if (path === "/applicability" && request.method === "POST") {
      return this.applicabilityBind(request);
    }
    // The dedicated model surface (deposit semantics; the native does
    // not mount the generic subregister here).
    if (path === "/models" && request.method === "GET") return this.listModels(url);
    if (path === "/models" && request.method === "POST") return this.depositModel(request);
    const modelValidate = path.match(/^\/models\/([^/]+)\/validate$/);
    if (modelValidate && request.method === "POST") {
      return this.validateModel(decodeURIComponent(modelValidate[1]));
    }
    const modelOne = path.match(/^\/models\/([^/]+)$/);
    if (modelOne && request.method === "GET") {
      return this.getModel(url, decodeURIComponent(modelOne[1]));
    }
    // The dedicated cross-register-mapping surface (the directional
    // lookup rides the collection route).
    if (path === "/cross-register-mappings" && request.method === "GET") {
      return this.mappingsGetOrList(url);
    }
    if (path === "/cross-register-mappings" && request.method === "POST") {
      return this.create(request, "cross-register-mapping");
    }
    const mappingVersions = path.match(/^\/cross-register-mappings\/([^/]+)\/versions$/);
    if (mappingVersions && request.method === "POST") {
      return this.supersede(request, decodeURIComponent(mappingVersions[1]), url, "cross-register-mapping");
    }
    const mappingChain = path.match(/^\/cross-register-mappings\/([^/]+)\/supersession$/);
    if (mappingChain && request.method === "GET") {
      return this.itemChainRoute(url, decodeURIComponent(mappingChain[1]), "cross-register-mapping");
    }
    const mappingOne = path.match(/^\/cross-register-mappings\/([^/]+)$/);
    if (mappingOne && request.method === "GET") {
      return this.getOneScoped(url, decodeURIComponent(mappingOne[1]), "cross-register-mapping");
    }
    // The discovery surface (C3 services, C4 protocol bindings, C5
    // verification mechanisms).
    if (path === "/services" && request.method === "GET") return this.listServices(url);
    if (path === "/services" && request.method === "POST") return this.createService(request);
    const serviceVersions = path.match(/^\/services\/([^/]+)\/versions$/);
    if (serviceVersions && request.method === "POST") {
      return this.supersedeServiceRoute(request, decodeURIComponent(serviceVersions[1]));
    }
    const serviceChain = path.match(/^\/services\/([^/]+)\/supersession$/);
    if (serviceChain && request.method === "GET") {
      return this.serviceChainRoute(url, decodeURIComponent(serviceChain[1]));
    }
    const serviceOne = path.match(/^\/services\/([^/]+)$/);
    if (serviceOne && request.method === "GET") {
      return this.getService(url, decodeURIComponent(serviceOne[1]));
    }
    if (path === "/protocol-bindings" && request.method === "GET") {
      return this.listProtocolBindings();
    }
    if (path === "/protocol-bindings" && request.method === "POST") {
      return this.createProtocolBinding(request);
    }
    const bindingOne = path.match(/^\/protocol-bindings\/([^/]+)$/);
    if (bindingOne && request.method === "GET") {
      return this.getProtocolBinding(decodeURIComponent(bindingOne[1]));
    }
    if (path === "/verification-mechanisms" && request.method === "GET") {
      return this.listVerificationMechanisms();
    }
    if (path === "/verification-mechanisms" && request.method === "POST") {
      return this.createVerificationMechanism(request);
    }
    const mechanismOne = path.match(/^\/verification-mechanisms\/([^/]+)$/);
    if (mechanismOne && request.method === "GET") {
      return this.getVerificationMechanism(decodeURIComponent(mechanismOne[1]));
    }
    // The generic subregister mounts: create, versions and
    // supersession at each class plural (the native nests one generic
    // handler at every plural except models and
    // cross-register-mappings, which carry dedicated surfaces above).
    const subCreate = path.match(/^\/([a-z-]+)$/);
    if (subCreate && request.method === "POST") {
      const singular = this.genericSubClass(subCreate[1]);
      if (!singular) return notFound("no such path");
      return this.create(request, singular);
    }
    const subVersions = path.match(/^\/([a-z-]+)\/([^/]+)\/versions$/);
    if (subVersions && request.method === "POST") {
      const singular = this.genericSubClass(subVersions[1]);
      if (!singular) return notFound("no such path");
      return this.supersede(request, decodeURIComponent(subVersions[2]), url, singular);
    }
    const subChain = path.match(/^\/([a-z-]+)\/([^/]+)\/supersession$/);
    if (subChain && request.method === "GET") {
      const singular = this.genericSubClass(subChain[1]);
      if (!singular) return notFound("no such path");
      return this.itemChainRoute(url, decodeURIComponent(subChain[2]), singular);
    }
    // The plural subregister listing (`/{class}`): the item listing
    // class-filtered.
    const plural = path.match(/^\/([a-z-]+)$/);
    if (plural && request.method === "GET") {
      const name = plural[1];
      const singular =
        Object.entries(CLASS_PLURALS).find(([, p]) => p === name)?.[0] ??
        (ITEM_CLASSES.includes(name) ? name : null);
      if (!singular) return notFound("no such path");
      const inner = new URL(request.url);
      inner.searchParams.set("class", singular);
      return this.list(inner);
    }
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

  // The class-generic subregister's class (the native nests the
  // generic handler at every plural except models and
  // cross-register-mappings, which carry dedicated surfaces).
  private genericSubClass(pluralName: string): string | null {
    const singular = Object.entries(CLASS_PLURALS).find(
      ([, p]) => p === pluralName,
    )?.[0];
    if (!singular || singular === "model" || singular === "cross-register-mapping") {
      return null;
    }
    return singular;
  }

  // The root discovery document (the native root handler's json!).
  private discoveryRoot(): Response {
    const descriptors = this.state
      .allItems()
      .filter((i) => i.item_class === "class-descriptor")
      .map(classDescriptorJson);
    return stamped(200, {
      service: "unidpp-registry",
      version: "0.1.0",
      build_id: "dev",
      description:
        "UniDPP ISO 19135 register service: item registration, version supersession, point-in-time resolution, applicability bindings, and the discovery registry (C3 services, C4 protocol bindings, C5 verification mechanisms)",
      endpoints: {
        register_item: "POST /items",
        list_items: "GET /items?class=&register=&at=",
        item_as_of: "GET /items/{id}?at=",
        supersede: "POST /items/{id}/versions",
        supersession_chain: "GET /items/{id}/supersession?from=",
        bind_applicability: "POST /applicability",
        applicability_as_of: "GET /applicability?product_type=&at=",
        register_service: "POST /services",
        list_services: "GET /services?class=&jurisdiction=&at=",
        service_as_of: "GET /services/{id}?at=",
        supersede_service: "POST /services/{id}/versions",
        service_supersession: "GET /services/{id}/supersession?from=",
        register_protocol_binding: "POST /protocol-bindings",
        list_protocol_bindings: "GET /protocol-bindings",
        protocol_binding: "GET /protocol-bindings/{id}",
        register_verification_mechanism: "POST /verification-mechanisms",
        list_verification_mechanisms: "GET /verification-mechanisms",
        verification_mechanism: "GET /verification-mechanisms/{id}",
        profile_manifest_schema: "GET /schemas/profile-manifest",
        deposit_model:
          "POST /models (EXPRESS source + metadata; content hash + expressir validation)",
        list_models: "GET /models?register=&at=",
        model_as_of: "GET /models/{id}?at=&hash= (hash-pinned retrieval)",
        validate_model: "POST /models/{id}/validate",
        list_cross_register_mappings:
          "GET /cross-register-mappings?item=&source=&target=&register=&at=",
        applicability_subject_facts:
          "GET /applicability?product_type=&at=&subject_facts=<json> (or POST with {product_type, at, subject_facts}) — evaluates clock predicates",
        audit_log: "GET /admin/log?limit=&offset=",
        seed: "POST /admin/seed",
        health: "GET /healthz",
      },
      item_classes: ITEM_CLASSES,
      statuses: STATUSES,
      service_classes: SERVICE_CLASSES,
      service_statuses: SERVICE_STATUSES,
      subregisters: subregistersJson(),
      as_of: {
        query_parameter: "at (alias: asof)",
        response_header: "x-as-of",
      },
      content_negotiation: {
        default: "application/json",
        "text/cddal":
          "collection reads (GET /items and the subregister listings) serve the canonical CDDAL plain-text dictionary form when Accept lists text/cddal — see README 'CDDAL serialization'",
        unknown_accept:
          "an Accept header listing nothing servable falls back to JSON with the x-content-negotiation: unknown-accept-fallback warning header",
      },
      discovery: {
        service_descriptor_signature:
          "Ed25519 over canonical-JSON of body (signature block excluded); operator id is content-derived from the public key",
        operator_keyring:
          "seeded dev keyring: unidpp-{registry,issuer,resolver,trust,log,archive,cli-verifier,edge}; loaded at startup; signatures are verified at intake only (replay re-applies the stored record)",
      },
      intake_checks: [
        "profile-signature-required",
        "profile-manifest-schema",
        "profile-satisfiability",
        "cross-register-mapping-integrity",
        "class-descriptor-signature-required",
        "class-descriptor-manifest",
        "instance-against-class",
      ],
      class_descriptors: descriptors,
      model_validation:
        "expressir (gem install expressir; `expressir validate load` run as a subprocess); deposits without expressir on PATH are stored with validation.status = pending",
      auth: "mutations require a Bearer token when UNIDPP_REGISTRY_ADMIN_TOKEN is set",
    }, isoNow());
  }

  // The audit log: the journal window, paged (the native
  // `Store::log_json` — default 100 records, maximum 10 000).
  private adminLog(url: URL): Response {
    const params = url.searchParams;
    const limitParam = Number(params.get("limit"));
    const limit = Math.min(
      Number.isInteger(limitParam) && limitParam > 0 ? limitParam : 100,
      10_000,
    );
    const offsetParam = Number(params.get("offset"));
    const offset = Number.isInteger(offsetParam) && offsetParam > 0 ? offsetParam : 0;
    const ops = this.state.journalOps();
    const records = ops
      .slice(offset, offset + limit)
      .map((op, index) => auditRecordJson(op, offset + index + 1));
    return stamped(200, { total: ops.length, offset, records }, isoNow());
  }

  // The seed dataset: the units subregister + the discovery corpus
  // (idempotent — one run per DO instance, records already present
  // are skipped).
  private async adminSeed(): Promise<Response> {
    if (this.seeded) {
      return stamped(200, { status: "already-seeded" }, isoNow());
    }
    const counts = {
      services: 0,
      protocol_bindings: 0,
      verification_mechanisms: 0,
      units: 0,
    };
    for (const [id, name, citation] of SEED_UNITS) {
      if (this.state.item(id)) continue;
      await this.state.registerItem({
        identifier: id,
        register: "unidpp-seed",
        item_class: "unit",
        title: name,
        submitting_organization: "ISO/TC 12",
        versions: [
          {
            version: "1.0.0",
            status: "valid",
            effective_from: "2026-01-01T00:00:00Z",
            effective_until: null,
            registered_at: isoNow(),
            superseded_by_version: null,
            notes: citation,
          },
        ],
        manifest: {
          version: "1.0.0",
          name,
          iso_80000_citation: citation,
        },
      });
      counts.units += 1;
    }
    for (const seed of SEED_DISCOVERY as (SeedProtocolBinding | SeedVerificationMechanism | SeedService)[]) {
      if (seed.kind === "pb") {
        const identifier = seed.body["identifier"] as string;
        if (this.state.protocolBinding(identifier)) continue;
        const parsed = parseProtocolBody(seed.body);
        await this.state.registerProtocolBinding({
          identifier,
          grammar_ref: parsed.grammar_ref,
          media_types: parsed.media_types,
          version: (seed.body["version"] as string) ?? "1.0.0",
          conformance_suite_ref: parsed.conformance_suite_ref,
          body: seed.body,
          signature: seed.signature,
        });
        counts.protocol_bindings += 1;
      } else if (seed.kind === "vm") {
        const identifier = seed.body["identifier"] as string;
        if (this.state.verificationMechanism(identifier)) continue;
        const parsed = parseVerificationBody(seed.body);
        await this.state.registerVerificationMechanism({
          identifier,
          suite: parsed.suite,
          agility_status: parsed.agility_status,
          trust_framework: parsed.trust_framework,
          trust_list_endpoint: parsed.trust_list_endpoint,
          master_list_ref: parsed.master_list_ref,
          verdict_grammar_ref: parsed.verdict_grammar_ref,
          body: seed.body,
          signature: seed.signature,
        });
        counts.verification_mechanisms += 1;
      } else {
        if (this.state.service(seed.identifier)) continue;
        await this.state.registerService({
          identifier: seed.identifier,
          versions: [
            {
              version: seed.version.version,
              status: seed.version.status,
              effective_from: seed.version.effective_from,
              effective_until: null,
              registered_at: isoNow(),
              superseded_by_version: null,
              body: seed.version.body,
              signature: seed.version.signature,
            },
          ],
        });
        counts.services += 1;
      }
    }
    this.seeded = true;
    return stamped(200, { status: "seeded", counts }, isoNow());
  }

  // The generated JSON Schema of a profile manifest, as-of stamped.
  private profileManifestSchema(url: URL): Response {
    let at: Date | null;
    try {
      at = parseAt(url.searchParams).at;
    } catch (e) {
      return badRequest((e as Error).message);
    }
    const asOf = at ?? new Date();
    const doc = {
      ...profileManifestSchema(),
      as_of: asOf.toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
    return stampedWith(200, doc, "application/schema+json", isoNow());
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

  private async create(request: Request, scope?: string): Promise<Response> {
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
    let itemClass: string;
    if (scope) {
      // The class-generic mount fixes the class: a body naming one
      // must name this mount's.
      const given = v["class"];
      if (typeof given === "string") {
        if (!ITEM_CLASSES.includes(given)) {
          return badRequest(`unknown item class \`${given}\``);
        }
        if (given !== scope) {
          return badRequest(
            `class \`${given}\` does not match subregister \`${CLASS_PLURALS[scope]}\``,
          );
        }
      }
      itemClass = scope;
    } else {
      itemClass = (v.class as string | undefined) ?? "data-element";
      if (!ITEM_CLASSES.includes(itemClass)) {
        return badRequest(`unknown item class \`${itemClass}\``);
      }
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
    const tierForm = itemClass === "cross-register-mapping" && manifest?.["kind"] !== undefined;
    if (manifest && !tierForm) {
      const pinned = manifest["version"];
      if (pinned !== version) {
        return badRequest("manifest `version` must be pinned to a registered version of the item");
      }
    }
    // The class-scoped intake chain (clause 5; R10 B1 + B2 + G7),
    // run in the native order with its first-failing-check semantics:
    // the descriptor's signed form, then its shape; the instance
    // against its descriptor; the mapping's tier duties. The refusal
    // is the native's intake form — the check names the item, the
    // failures ride beside it.
    const intake = (failures: IntakeFailure[]): Response => intakeResponse(failures, isoNow());
    if (itemClass === "class-descriptor") {
      const signed = descriptorSignatureErrors(manifest);
      if (signed.length > 0) return intake(signed);
      const shaped = descriptorManifestErrors(identifier, manifest ?? {});
      if (shaped.length > 0) return intake(shaped);
    } else if (itemClass === "instance") {
      const against = instanceErrors(manifest, this.state);
      if (against.length > 0) return intake(against);
    } else if (itemClass === "cross-register-mapping" && manifest?.["kind"] !== undefined) {
      // The clause-15 tier form rides its own duties.
      const tiered = mappingTierErrors(manifest, this.state);
      if (tiered.length > 0) return intake(tiered);
    } else if (itemClass === "profile") {
      // The profile's signed form (the chain's first profile check).
      const signed = profileSignatureErrors(manifest);
      if (signed.length > 0) return intake(signed);
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

  private async supersede(
    request: Request,
    identifier: string,
    url: URL,
    scope?: string,
  ): Promise<Response> {
    void url;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const item = this.state.item(identifier);
    // The class-generic mount resolves the item through its class: a
    // version POST for an id of another class is the item miss.
    if (!item || (scope && item.item_class !== scope)) {
      return notFound(`no registry item \`${identifier}\``);
    }
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
    const supersedeTierForm =
      item.item_class === "cross-register-mapping" && manifest?.["kind"] !== undefined;
    if (manifest && !supersedeTierForm) {
      const pinned = manifest["version"];
      if (pinned !== version) {
        return badRequest("manifest `version` must be pinned to a registered version of the item");
      }
    }
    if (manifest) {
      // The same class-scoped chain gates a superseding manifest.
      if (item.item_class === "class-descriptor" || item.item_class === "instance") {
        const scoped =
          item.item_class === "class-descriptor"
            ? (() => {
                const signed = descriptorSignatureErrors(manifest);
                if (signed.length > 0) return signed;
                return descriptorManifestErrors(identifier, manifest);
              })()
            : instanceErrors(manifest, this.state);
        if (scoped.length > 0) {
          return intakeResponse(scoped, isoNow());
        }
      }
      if (supersedeTierForm) {
        const scoped = mappingTierErrors(manifest, this.state);
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

  // GET /items/{id}/supersession (and its class-generic mounts): the
  // supersession chain, terminal last.
  private itemChainRoute(url: URL, identifier: string, scope?: string): Response {
    let params: URLSearchParams;
    try {
      params = url.searchParams;
      const { at, asOf } = parseAt(params);
      const item = this.state.item(identifier);
      if (!item || (scope && item.item_class !== scope)) {
        return notFound(`no registry item \`${identifier}\``);
      }
      const chain = itemSupersessionChain(item, optQuery(params, "from"));
      const rendered = chain.map((ver) => {
        const view = plainVersionJson(ver);
        const windowEnd = windowUntil(item, ver);
        if (windowEnd) view.window_end = windowEnd;
        return view;
      });
      return stamped(
        200,
        {
          identifier,
          chain: rendered,
          terminal: rendered.length > 0 ? rendered[rendered.length - 1] : null,
          as_of: (at ?? asOf).toISOString().replace(/\.\d{3}Z$/, "Z"),
        },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // GET /applicability?product_type=&at=&subject_facts= — which
  // profiles applied at `at`, with the clock predicates evaluated
  // when the subject's facts were supplied.
  private applicabilityQuery(url: URL): Response {
    let params: URLSearchParams;
    try {
      params = url.searchParams;
      const { at } = parseAt(params);
      const subject = optQuery(params, "product_type") ?? optQuery(params, "subject");
      if (!subject) return badRequest("`product_type` is required");
      const factsRaw = params.get("subject_facts");
      let facts: Record<string, unknown> | undefined;
      if (factsRaw !== null) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(factsRaw);
        } catch (e) {
          return badRequest(`\`subject_facts\` must be a JSON object: ${(e as Error).message}`);
        }
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return badRequest("`subject_facts` must be a JSON object");
        }
        facts = parsed as Record<string, unknown>;
      }
      const doc = this.evaluateApplicability(subject, at, facts);
      return stamped(200, doc, isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // POST /applicability — bind a profile to a product type; a body
  // carrying `subject_facts` (and no profile to bind) is an
  // evaluation request, not a mutation.
  private async applicabilityBind(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    if (v["subject_facts"] !== undefined) {
      if (v["profile_id"] !== undefined) {
        return badRequest(
          "cannot bind with `subject_facts`: subject_facts marks an evaluation request (drop `profile_id`)",
        );
      }
      const subject = optBodyString(v, "product_type") ?? optBodyString(v, "subject");
      if (!subject) return badRequest("`product_type` is required");
      const facts = v["subject_facts"];
      if (!facts || typeof facts !== "object" || Array.isArray(facts)) {
        return badRequest("`subject_facts` must be a JSON object");
      }
      let at: Date | null;
      try {
        at = optTimestamp(v, "at");
      } catch (e) {
        return badRequest((e as Error).message);
      }
      const doc = this.evaluateApplicability(subject, at, facts as Record<string, unknown>);
      return stamped(200, doc, isoNow());
    }
    const profileItem = (v["profile_id"] as string)?.trim();
    if (!profileItem) return badRequest("`profile_id` is required");
    if (!tokenOk(profileItem)) {
      return badRequest("`profile_id` must be 1-256 characters without `/` or whitespace");
    }
    const subject = optBodyString(v, "product_type") ?? optBodyString(v, "subject");
    if (!subject) {
      return badRequest(
        v["product_type"] === undefined && v["subject"] === undefined
          ? "`product_type` is required"
          : "`product_type` must be a non-empty string",
      );
    }
    let register: string | null;
    try {
      register = optNonEmptyString(v, "register");
    } catch {
      return badRequest("`register` must be a non-empty string");
    }
    let profileVersion: string | null;
    try {
      profileVersion = optNonEmptyString(v, "profile_version");
    } catch {
      return badRequest("`profile_version` must be a non-empty string");
    }
    const effectiveFrom = (v["effective_from"] as string | undefined) ?? isoNow();
    const effectiveUntil = (v["effective_until"] as string | undefined) ?? null;
    if (effectiveUntil && new Date(effectiveUntil) <= new Date(effectiveFrom)) {
      return badRequest("`effective_until` must be after `effective_from`");
    }
    const retroactive = v["retroactive"] === true;
    // The profile the binding names must exist and be of class
    // `profile`; a pinned version must be a registered version of it.
    const profile = this.state.item(profileItem);
    if (!profile) {
      return badRequest(`profile item \`${profileItem}\` is not registered`);
    }
    if (profile.item_class !== "profile") {
      return badRequest(`item \`${profileItem}\` has class \`${profile.item_class}\`, not \`profile\``);
    }
    if (
      profileVersion &&
      !profile.versions.some((existing) => existing.version === profileVersion)
    ) {
      return badRequest(`item \`${profileItem}\` has no version \`${profileVersion}\``);
    }
    const auditSeq = await this.state.bind({
      id: 0,
      subject,
      profile_item: profileItem,
      register: register ?? null,
      profile_version: profileVersion ?? null,
      effective_from: effectiveFrom,
      effective_until: effectiveUntil,
      registered_at: isoNow(),
      retroactive,
    });
    const bound = this.state.bindingsFor(subject).slice(-1)[0]!;
    const body = bindingJson(bound);
    body["audit_seq"] = auditSeq;
    body["as_of"] = isoNow();
    return stamped(201, body, isoNow());
  }

  // The applicability evaluation core, shared by the GET and POST
  // forms: the bindings' as-of machinery, then — only when subject
  // facts were supplied — each bound profile's clock predicates at
  // the same instant.
  private evaluateApplicability(
    subject: string,
    at: Date | null,
    facts?: Record<string, unknown>,
  ): Record<string, unknown> {
    const asOf = at ?? new Date();
    const applicability: Record<string, unknown>[] = [];
    const unresolved: Record<string, unknown>[] = [];
    for (const binding of this.state.bindingsFor(subject)) {
      if (!bindingAppliesAt(binding, asOf)) continue;
      const profile = this.state.item(binding.profile_item);
      let triggers: [number, TimeTrigger][];
      try {
        triggers = profile?.manifest ? timeTriggers(profile.manifest) : [];
      } catch (e) {
        return { error: `profile \`${binding.profile_item}\` carries a malformed time trigger: ${(e as Error).message}` };
      }
      if (triggers.length === 0) {
        applicability.push({
          binding: bindingJson(binding),
          profile: profile ? itemSummary(profile, at, asOf) : null,
        });
        continue;
      }
      // clock-fired applicability: the registry can only decide with
      // the subject's facts
      if (!facts) {
        unresolved.push({
          binding: bindingJson(binding),
          profile_item: binding.profile_item,
          reason:
            "the profile's triggers are clock predicates; supply subject_facts to evaluate them",
        });
        continue;
      }
      const evaluations: Record<string, unknown>[] = [];
      let binds = true;
      const atSecs = Math.floor(asOf.getTime() / 1000);
      for (const [index, trigger] of triggers) {
        try {
          const evaluation = evaluateTrigger(trigger, facts, atSecs);
          if (!evaluation.satisfied) binds = false;
          evaluations.push({
            index,
            basis: trigger.basis,
            operator: trigger.operator,
            duration: trigger.duration_raw,
            threshold: evaluation.threshold,
            satisfied: evaluation.satisfied,
          });
        } catch {
          // a subject that does not carry the basis fact is not in
          // the predicate's scope
          binds = false;
        }
      }
      if (binds) {
        applicability.push({
          binding: bindingJson(binding),
          profile: profile ? itemSummary(profile, at, asOf) : null,
          time_triggers: evaluations,
        });
      }
    }
    return {
      as_of: asOf.toISOString().replace(/\.\d{3}Z$/, "Z"),
      product_type: subject,
      applicability,
      unresolved,
    };
  }

  // `GET /services` — the class/jurisdiction filters ride the current
  // version's body (the native `services_filtered`).
  private listServices(url: URL): Response {
    try {
      const { at, asOf } = parseAt(url.searchParams);
      const classFilter = optQuery(url.searchParams, "class");
      if (classFilter && !SERVICE_CLASSES.includes(classFilter)) {
        return badRequest(
          `unknown service class \`${classFilter}\` (expected one of ${SERVICE_CLASSES.join(", ")})`,
        );
      }
      const jurisdiction = optQuery(url.searchParams, "jurisdiction");
      const services = this.state
        .allServices()
        .map((descriptor) => ({ descriptor, current: currentServiceVersion(descriptor) }))
        .filter(({ current }) => current !== undefined)
        .filter(({ current }) => {
          if (!classFilter) return true;
          return current!.body["class"] === classFilter;
        })
        .filter(({ current }) => {
          if (!jurisdiction) return true;
          return current!.body["jurisdiction"] === jurisdiction;
        })
        .map(({ descriptor }) => serviceDescriptorJson(descriptor, asOf.toISOString().replace(/\.\d{3}Z$/, "Z"), at));
      return stamped(
        200,
        { as_of: asOf.toISOString().replace(/\.\d{3}Z$/, "Z"), count: services.length, services },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `POST /services` — register a signed C3 service descriptor. The
  // structural intake runs here; the keyring's cryptographic
  // verification rides the native.
  private async createService(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const identifier = (v["identifier"] as string)?.trim();
    if (!identifier) return badRequest("`identifier` is required");
    if (!tokenOk(identifier)) {
      return badRequest("`identifier` must be 1-256 characters without `/` or whitespace");
    }
    return this.serviceMutation(v, identifier, "create");
  }

  // `POST /services/{id}/versions` — supersede a service descriptor
  // with a new signed version (existence first: an unknown service is
  // a 404 regardless of what the body says).
  private async supersedeServiceRoute(request: Request, identifier: string): Promise<Response> {
    if (!this.state.service(identifier)) {
      return notFound(`no service descriptor \`${identifier}\``);
    }
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    return this.serviceMutation(v, identifier, "supersede");
  }

  // The C3 mutation core shared by the create and supersede routes
  // (the native's parse → verify → store order). The create refuses
  // an existing identifier (409); the supersede routes through the
  // active-version checks.
  private async serviceMutation(
    v: Record<string, unknown>,
    identifier: string,
    mode: "create" | "supersede",
  ): Promise<Response> {
    const version = (v["version"] as string)?.trim();
    if (!version) return badRequest("`version` is required");
    if (!tokenOk(version)) {
      return badRequest("`version` must be 1-256 characters without `/` or whitespace");
    }
    const bodyVal = v["body"];
    if (bodyVal === undefined) return badRequest("missing `body`");
    let signature: DiscoverySignature;
    try {
      if (v["signature"] === undefined) return badRequest("missing `signature`");
      signature = signatureFromJson(v["signature"]);
    } catch (e) {
      return badRequest(`\`signature\`: ${(e as Error).message}`);
    }
    const effectiveFrom = (v["effective_from"] as string | undefined) ?? isoNow();
    const effectiveUntil = (v["effective_until"] as string | undefined) ?? null;
    if (effectiveUntil && new Date(effectiveUntil) <= new Date(effectiveFrom)) {
      return badRequest("`effective_until` must be after `effective_from`");
    }
    const supersedeVersion = optBodyString(v, "supersede_version");
    try {
      const parsed = await parseServiceBody(bodyVal, identifier);
      // The key id in the signature must match the content-derived
      // key id of the operator's public key (catches cross-key
      // forgeries; the signature bytes themselves verify against the
      // keyring, which the edge does not carry).
      const expectedKeyId = await operatorKeyIdOf(parsed.operator.public_key);
      if (signature.key_id !== expectedKeyId) {
        return badRequest(
          this.state.service(identifier)
            ? `signature \`key_id\` \`${signature.key_id}\` does not match the content-derived key id \`${expectedKeyId}\``
            : `signature \`key_id\` \`${signature.key_id}\` does not match the content-derived key id \`${expectedKeyId}\` for operator \`${parsed.operator.id}\``,
        );
      }
      const now = isoNow();
      const svcVersion: ServiceVersionRec = {
        version,
        status: parsed.status,
        effective_from: effectiveFrom,
        effective_until: effectiveUntil,
        registered_at: now,
        superseded_by_version: null,
        body: bodyVal as Record<string, unknown>,
        signature,
      };
      const existing = this.state.service(identifier);
      if (!existing) {
        if (mode === "supersede") {
          // The supersede route resolves the descriptor first; this
          // is reachable only when it raced away.
          return notFound(`no service descriptor \`${identifier}\``);
        }
        const auditSeq = await this.state.registerService({
          identifier,
          versions: [svcVersion],
        });
        return stamped(201, {
          identifier,
          version: serviceVersionJson(svcVersion, null),
          audit_seq: auditSeq,
          as_of: now,
        }, now);
      }
      if (mode === "create") {
        return conflict(
          `service \`${identifier}\` is already registered; add versions through POST /services/${identifier}/versions`,
        );
      }
      if (existing.versions.some((candidate) => candidate.version === version)) {
        return conflict(`service \`${identifier}\` already has a version \`${version}\``);
      }
      let target: ServiceVersionRec | undefined;
      if (supersedeVersion) {
        target = existing.versions.find((candidate) => candidate.version === supersedeVersion);
        if (!target) {
          return badRequest(`service \`${identifier}\` has no version \`${supersedeVersion}\``);
        }
      } else {
        target = currentServiceVersion(existing);
        if (!target || target.status !== "active") {
          return badRequest(`service \`${identifier}\` has no active version to supersede`);
        }
      }
      if (target.status !== "active") {
        return badRequest(
          `service version \`${target.version}\` of \`${identifier}\` is ${target.status} — only the active version can be superseded`,
        );
      }
      if (new Date(effectiveFrom) < new Date(target.effective_from)) {
        return badRequest(
          "new version's `effective_from` precedes the superseded version's window start",
        );
      }
      const auditSeq = await this.state.supersedeService(identifier, target.version, svcVersion);
      const after = this.state.service(identifier)!;
      const newVersion = after.versions.find((candidate) => candidate.version === version)!;
      const oldVersion = after.versions.find((candidate) => candidate.version === target!.version)!;
      return stamped(201, {
        identifier,
        new_version: serviceVersionJson(newVersion, serviceWindowUntil(after, newVersion)),
        superseded_version: serviceVersionJson(oldVersion, serviceWindowUntil(after, oldVersion)),
        audit_seq: auditSeq,
        as_of: now,
      }, now);
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `GET /services/{id}` — the descriptor with the version in force
  // at `at`.
  private getService(url: URL, identifier: string): Response {
    try {
      const { at, asOf } = parseAt(url.searchParams);
      const descriptor = this.state.service(identifier);
      if (!descriptor) return notFound(`no service descriptor \`${identifier}\``);
      const asOfText = asOf.toISOString().replace(/\.\d{3}Z$/, "Z");
      return stamped(200, serviceDescriptorJson(descriptor, asOfText, at), isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `GET /services/{id}/supersession` — the chain of a C3 descriptor.
  private serviceChainRoute(url: URL, identifier: string): Response {
    try {
      const { at, asOf } = parseAt(url.searchParams);
      const descriptor = this.state.service(identifier);
      if (!descriptor) return notFound(`no service descriptor \`${identifier}\``);
      const chain = serviceSupersessionChain(descriptor, optQuery(url.searchParams, "from"));
      const rendered = chain.map((v) =>
        serviceVersionJson(v, serviceWindowUntil(descriptor, v)),
      );
      return stamped(
        200,
        {
          identifier,
          chain: rendered,
          terminal: rendered.length > 0 ? rendered[rendered.length - 1] : null,
          as_of: (at ?? asOf).toISOString().replace(/\.\d{3}Z$/, "Z"),
        },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `POST /protocol-bindings` — register a signed C4 descriptor.
  private async createProtocolBinding(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const identifier = (v["identifier"] as string)?.trim();
    if (!identifier) return badRequest("`identifier` is required");
    if (!tokenOk(identifier)) {
      return badRequest("`identifier` must be 1-256 characters without `/` or whitespace");
    }
    const version = (v["version"] as string)?.trim();
    if (!version) return badRequest("`version` is required");
    if (!tokenOk(version)) {
      return badRequest("`version` must be 1-256 characters without `/` or whitespace");
    }
    const bodyVal = v["body"];
    if (bodyVal === undefined) return badRequest("missing `body`");
    let signature: DiscoverySignature;
    try {
      if (v["signature"] === undefined) return badRequest("missing `signature`");
      signature = signatureFromJson(v["signature"]);
    } catch (e) {
      return badRequest(`\`signature\`: ${(e as Error).message}`);
    }
    try {
      const parsed = parseProtocolBody(bodyVal);
      // The operator block rides the body; the keyring's
      // cryptographic verification rides the native.
      const bodyObject = bodyVal as Record<string, unknown>;
      if (bodyObject["operator"] === undefined) {
        return badRequest("body missing `operator`");
      }
      await operatorFromJson(bodyObject["operator"]).catch((e) => {
        throw new Error(`\`operator\`: ${(e as Error).message}`);
      });
      if (this.state.protocolBinding(identifier)) {
        return conflict(`protocol binding \`${identifier}\` is already registered`);
      }
      const rec: ProtocolBindingRec = {
        identifier,
        grammar_ref: parsed.grammar_ref,
        media_types: parsed.media_types,
        version,
        conformance_suite_ref: parsed.conformance_suite_ref,
        body: bodyVal as Record<string, unknown>,
        signature,
      };
      const auditSeq = await this.state.registerProtocolBinding(rec);
      return stamped(201, {
        identifier,
        binding: protocolBindingJson(rec),
        audit_seq: auditSeq,
        as_of: isoNow(),
      }, isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `GET /protocol-bindings` — all registered C4 descriptors.
  private listProtocolBindings(): Response {
    const bindings = this.state.allProtocolBindings().map(protocolBindingJson);
    return stamped(
      200,
      { as_of: isoNow(), count: bindings.length, protocol_bindings: bindings },
      isoNow(),
    );
  }

  // `GET /protocol-bindings/{id}` — one C4 descriptor.
  private getProtocolBinding(identifier: string): Response {
    const binding = this.state.protocolBinding(identifier);
    if (!binding) return notFound(`no protocol binding \`${identifier}\``);
    return stamped(200, protocolBindingJson(binding), isoNow());
  }

  // `POST /verification-mechanisms` — register a signed C5 mechanism.
  private async createVerificationMechanism(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const identifier = (v["identifier"] as string)?.trim();
    if (!identifier) return badRequest("`identifier` is required");
    if (!tokenOk(identifier)) {
      return badRequest("`identifier` must be 1-256 characters without `/` or whitespace");
    }
    const bodyVal = v["body"];
    if (bodyVal === undefined) return badRequest("missing `body`");
    let signature: DiscoverySignature;
    try {
      if (v["signature"] === undefined) return badRequest("missing `signature`");
      signature = signatureFromJson(v["signature"]);
    } catch (e) {
      return badRequest(`\`signature\`: ${(e as Error).message}`);
    }
    try {
      const parsed = parseVerificationBody(bodyVal);
      // The operator block rides the body; the keyring's
      // cryptographic verification rides the native.
      const bodyObject = bodyVal as Record<string, unknown>;
      if (bodyObject["operator"] === undefined) {
        return badRequest("body missing `operator`");
      }
      await operatorFromJson(bodyObject["operator"]).catch((e) => {
        throw new Error(`\`operator\`: ${(e as Error).message}`);
      });
      if (this.state.verificationMechanism(identifier)) {
        return conflict(`verification mechanism \`${identifier}\` is already registered`);
      }
      const rec: VerificationMechanismRec = {
        identifier,
        suite: parsed.suite,
        agility_status: parsed.agility_status,
        trust_framework: parsed.trust_framework,
        trust_list_endpoint: parsed.trust_list_endpoint,
        master_list_ref: parsed.master_list_ref,
        verdict_grammar_ref: parsed.verdict_grammar_ref,
        body: bodyVal as Record<string, unknown>,
        signature,
      };
      const auditSeq = await this.state.registerVerificationMechanism(rec);
      return stamped(201, {
        identifier,
        mechanism: verificationMechanismJson(rec),
        audit_seq: auditSeq,
        as_of: isoNow(),
      }, isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `GET /verification-mechanisms` — all registered C5 mechanisms.
  private listVerificationMechanisms(): Response {
    const mechanisms = this.state.allVerificationMechanisms().map(verificationMechanismJson);
    return stamped(
      200,
      {
        as_of: isoNow(),
        count: mechanisms.length,
        verification_mechanisms: mechanisms,
      },
      isoNow(),
    );
  }

  // `GET /verification-mechanisms/{id}` — one C5 mechanism.
  private getVerificationMechanism(identifier: string): Response {
    const mechanism = this.state.verificationMechanism(identifier);
    if (!mechanism) return notFound(`no verification mechanism \`${identifier}\``);
    return stamped(200, verificationMechanismJson(mechanism), isoNow());
  }

  // `POST /models` — deposit an EXPRESS model: source text plus
  // metadata; the content hash covers the exact bytes. expressir
  // validates the source natively as a subprocess; the edge carries
  // no subprocess, so every deposit stores the documented degrade
  // (validation.status = pending).
  private async depositModel(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const register = (v["register_id"] as string)?.trim();
    if (!register) return badRequest("`register_id` is required");
    const identifier = (v["item_id"] as string)?.trim();
    if (!identifier) return badRequest("`item_id` is required");
    if (!tokenOk(identifier)) {
      return badRequest("`item_id` must be 1-256 characters without `/` or whitespace");
    }
    const title = (v["definition"] as string | undefined) ?? (v["title"] as string | undefined);
    if (!title || !title.trim()) return badRequest("`definition` is required");
    let submittingOrganization: string | null;
    try {
      submittingOrganization = optNonEmptyString(v, "submitting_organization");
    } catch {
      return badRequest("`submitting_organization` must be a non-empty string");
    }
    const version = (v["version"] as string)?.trim();
    if (!version) return badRequest("`version` is required");
    if (!tokenOk(version)) {
      return badRequest("`version` must be 1-256 characters without `/` or whitespace");
    }
    const source = v["source"];
    if (typeof source !== "string" || source === "") {
      return badRequest("`source` is required");
    }
    const contentHash = `sha256:${await sha256Hex([source])}`;
    const effectiveFrom = (v["effective_from"] as string | undefined) ?? isoNow();
    const effectiveUntil = (v["effective_until"] as string | undefined) ?? null;
    if (effectiveUntil && new Date(effectiveUntil) <= new Date(effectiveFrom)) {
      return badRequest("`effective_until` must be after `effective_from`");
    }
    const validation = {
      status: "pending",
      tool: "expressir",
      detail: "`expressir` is not available (gem install expressir)",
    };
    if (this.state.item(identifier)) {
      return badRequest(`item \`${identifier}\` already exists`);
    }
    const item: Item = {
      identifier,
      register,
      item_class: "model",
      title: title.trim(),
      submitting_organization: submittingOrganization ?? undefined,
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
      manifest: {
        version,
        express: {
          source,
          content_hash: contentHash,
          validation,
        },
      },
    };
    const auditSeq = await this.state.registerItem(item);
    return stamped(201, {
      identifier,
      item_class: "model",
      version,
      content_hash: contentHash,
      validation,
      audit_seq: auditSeq,
      as_of: isoNow(),
    }, isoNow());
  }

  // `GET /models` — the deposited models with their validation status.
  private listModels(url: URL): Response {
    try {
      const { at, asOf } = parseAt(url.searchParams);
      const register = optQuery(url.searchParams, "register");
      const models = this.state
        .allItems()
        .filter((i) => i.item_class === "model")
        .filter((i) => !register || i.register === register)
        .map((item) => {
          const summary = itemSummary(item, at, asOf);
          summary["validation"] = modelValidationStatus(item);
          return summary;
        });
      return stamped(
        200,
        { as_of: asOf.toISOString().replace(/\.\d{3}Z$/, "Z"), count: models.length, models },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `GET /models/{id}?at=&hash=` — the deposited source, its content
  // hash and validation status; a pinned hash names an exact byte
  // form (mismatch → 409).
  private getModel(url: URL, identifier: string): Response {
    try {
      const { at, asOf } = parseAt(url.searchParams);
      const item = this.state.item(identifier);
      if (!item || item.item_class !== "model") {
        return notFound(`no model item \`${identifier}\``);
      }
      const express = item.manifest?.["express"] as Record<string, unknown> | undefined;
      if (!express) return badRequest("model item carries no deposit manifest");
      const source = express["source"];
      const contentHash = express["content_hash"];
      if (typeof source !== "string" || typeof contentHash !== "string") {
        return badRequest("corrupt model manifest: missing `express` deposit fields");
      }
      const pinned = optQuery(url.searchParams, "hash");
      if (pinned && pinned !== contentHash) {
        return conflict(
          `content hash mismatch: the deposit is \`${contentHash}\` but \`${pinned}\` was pinned`,
        );
      }
      const body = itemView(item, at, asOf) as Record<string, unknown>;
      body["source"] = source;
      body["content_hash"] = contentHash;
      body["validation"] = express["validation"] ?? null;
      return stamped(200, body, isoNow());
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }

  // `POST /models/{id}/validate` — re-run expressir over the stored
  // source and record the outcome (the degrade path: the edge's
  // record stays pending until a validator is available).
  private async validateModel(identifier: string): Promise<Response> {
    const item = this.state.item(identifier);
    if (!item || item.item_class !== "model") {
      return notFound(`no model item \`${identifier}\``);
    }
    const express = item.manifest?.["express"] as Record<string, unknown> | undefined;
    if (!express) return badRequest("model item carries no deposit manifest");
    const current = item.versions[item.versions.length - 1]?.version;
    if (!current) return badRequest(`model \`${identifier}\` has no current version`);
    const validation = {
      status: "pending",
      tool: "expressir",
      detail: "`expressir` is not available (gem install expressir)",
    };
    await this.state.updateModelValidation(identifier, current, validation);
    return stamped(200, { identifier, validation, as_of: isoNow() }, isoNow());
  }

  // `GET /cross-register-mappings` — with `item`/`source`/`target`
  // filters, the directional lookup; without them, the generic
  // class-scoped listing.
  private async mappingsGetOrList(url: URL): Promise<Response> {
    const params = url.searchParams;
    const lookupItem = optQuery(params, "item");
    const source = optQuery(params, "source");
    const target = optQuery(params, "target");
    if (!lookupItem && !source && !target) {
      const inner = new URL(url.toString());
      inner.searchParams.set("class", "cross-register-mapping");
      return await this.list(inner);
    }
    try {
      const { at, asOf } = parseAt(params);
      const register = optQuery(params, "register");
      const mappings = this.state
        .allItems()
        .filter((i) => i.item_class === "cross-register-mapping")
        .filter((i) => !register || i.register === register)
        .filter((i) => mappingMatchesQuery(i, lookupItem, source, target))
        .map((item) => {
          const summary = itemSummary(item, at, asOf);
          if (item.manifest) summary["manifest"] = item.manifest;
          return summary;
        });
      return stamped(
        200,
        {
          as_of: asOf.toISOString().replace(/\.\d{3}Z$/, "Z"),
          count: mappings.length,
          mappings,
          query: { item: lookupItem, source, target },
        },
        isoNow(),
      );
    } catch (e) {
      return badRequest((e as Error).message);
    }
  }
}

export function mountClass(): string {
  return CLASS_PLURALS["data-element"];
}
