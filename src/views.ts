// The views surface on the estate (REARCH R12 S5-serve): the lens
// view computed through the wasm boundary — the same project() the
// native projector compiles. The passport rides the estate's own
// issuer DO; the lens item rides the estate's own registry DO (both
// in process); the fixtures fallback (the built-in EU/JP lens) rides
// the boundary's fixture module. /views/render is the same selection
// presented per the lens's presentation binding — the consumer
// render, in three wire formats (JSON, the standalone HTML page, the
// speakable text), exactly the native projector's split.

import { workerCore } from "./mount";

export interface DoNamespace {
  idFromName(name: string): { toString(): string };
  get(id: unknown): { fetch(request: Request): Promise<Response> };
}

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const asOfNow = (): string => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

const stamped = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": asOfNow(),
    },
  });

function project(
  passportText: string,
  lensText: string,
  atSecs: number,
  actor: string,
): { ok: true; view: Record<string, unknown> } | { ok: false; error: string } {
  const core = workerCore();
  const encoder = new TextEncoder();
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = encoder.encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const passport = put(passportText);
  const lens = put(lensText);
  const actorPart = put(actor);
  const rc = core.unidpp_view_project(
    passport.ptr,
    passport.len,
    lens.ptr,
    lens.len,
    BigInt(Math.floor(atSecs)),
    actorPart.ptr,
    actorPart.len,
  );
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  [passport.ptr, lens.ptr, actorPart.ptr].forEach((ptr) => core.unidpp_free(ptr, 0));
  if (rc === 0) {
    return { ok: true, view: JSON.parse(note) as Record<string, unknown> };
  }
  return { ok: false, error: note || `the projection failed (${rc})` };
}

// The built-in fixture lens: the native fixtures module's own, via
// the wasm boundary — byte-exact with the native fallback.

// The passport document: the estate's issuer DO first, the built-in
// demo passport as the stated fallback (the native fixtures
// doctrine). Returns the document text and where it came from, or
// the error response.
async function loadPassport(
  env: { ISSUER?: DoNamespace; tenant?: string },
  passportId: string,
): Promise<{ ok: true; text: string; fromFixtures: boolean } | { ok: false; response: Response }> {
  const estate = (ns: DoNamespace, name: string) =>
    ns.get(ns.idFromName(env.tenant ? `${name}@${env.tenant}` : name));
  if (env.ISSUER) {
    const stub = estate(env.ISSUER, "estate");
    const response = await stub.fetch(
      new Request(`https://do.internal/passports/${encodeURIComponent(passportId)}`),
    );
    if (response.status === 200) {
      const body = (await response.json()) as Record<string, unknown>;
      const document = { ...body };
      delete document.audit_seq;
      return { ok: true, text: JSON.stringify(document), fromFixtures: false };
    }
  }
  const core = workerCore();
  const rc = core.unidpp_fixture_passport();
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  const demo = rc === 0 ? (JSON.parse(note) as { passport_id: string }) : null;
  if (rc !== 0 || passportId !== demo?.passport_id) {
    return {
      ok: false,
      response: stamped(404, { error: `no passport \`${passportId}\`` }),
    };
  }
  return { ok: true, text: note, fromFixtures: true };
}

// The lens manifest: the estate's registry DO first, the built-in
// fixture otherwise. Returns the item text and its source, or the
// error response.
async function loadLens(
  env: { REGISTRY?: DoNamespace; tenant?: string },
  profile: string,
): Promise<{ ok: true; text: string; source: string } | { ok: false; response: Response }> {
  const estate = (ns: DoNamespace, name: string) =>
    ns.get(ns.idFromName(env.tenant ? `${name}@${env.tenant}` : name));
  if (env.REGISTRY) {
    const stub = estate(env.REGISTRY, "estate");
    const response = await stub.fetch(
      new Request(`https://do.internal/profiles/${encodeURIComponent(profile)}`),
    );
    if (response.status === 200) {
      return {
        ok: true,
        text: JSON.stringify(await response.json()),
        source: "registry",
      };
    }
  }
  const core = workerCore();
  const profileBytes = new TextEncoder().encode(profile);
  const profilePtr = core.unidpp_alloc(profileBytes.length);
  new Uint8Array(core.memory.buffer, profilePtr, profileBytes.length).set(profileBytes);
  const lensRc = core.unidpp_fixture_lens(profilePtr, profileBytes.length);
  core.unidpp_free(profilePtr, profileBytes.length);
  const notePtr = core.unidpp_alloc(1048576);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, 1048576);
  if (lensRc !== 0) {
    return {
      ok: false,
      response: stamped(404, { error: `no profile item \`${profile}\` in the registry` }),
    };
  }
  return { ok: true, text: note, source: "fixtures" };
}

export async function view(
  request: Request,
  env: {
    ISSUER?: DoNamespace;
    REGISTRY?: DoNamespace;
    tenant?: string;
  },
): Promise<Response> {
  if (new URL(request.url).pathname.endsWith("/render")) {
    return render(request, env);
  }
  const params = new URL(request.url).searchParams;
  const passportId = params.get("passport")?.trim();
  const profile = params.get("profile")?.trim();
  const actor = params.get("actor")?.trim() || "anonymous";
  if (!passportId) return badRequest("`passport` query parameter is required");
  if (!profile) return badRequest("`profile` query parameter is required");
  const at = params.get("at") ?? params.get("asof");
  const atSecs = at ? Math.floor(Date.parse(at) / 1000) : Math.floor(Date.now() / 1000);

  const passport = await loadPassport(env, passportId);
  if (!passport.ok) return passport.response;
  const lens = await loadLens(env, profile);
  if (!lens.ok) return lens.response;

  const minted = project(passport.text, lens.text, atSecs, actor);
  if (!minted.ok) return stamped(502, { error: minted.error });
  const viewDoc = minted.view as Record<string, unknown>;
  if (viewDoc.passport && typeof viewDoc.passport === "object") {
    (viewDoc.passport as Record<string, unknown>).source = passport.fromFixtures
      ? "fixtures"
      : lens.source;
  }
  return stamped(200, viewDoc);
}

// GET /views/render — the consumer presentation of the same selection
// the view serves (TODO.impl 54): the passport's data points arranged
// per the lens's presentation binding, localized and formatted, with
// links to the authoritative sources and the same coverage honesty.
// One presentation computation, three wire formats: JSON by default;
// Accept: text/html or text/plain (or an explicit `format` parameter,
// which outranks the header) serves the standalone page or the
// speakable text (the TTS substrate).
async function render(
  request: Request,
  env: {
    ISSUER?: DoNamespace;
    REGISTRY?: DoNamespace;
    tenant?: string;
  },
): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const passportId = params.get("passport")?.trim();
  const profile = params.get("profile")?.trim();
  const lang = params.get("lang")?.trim();
  if (!passportId) return badRequest("`passport` query parameter is required");
  if (!profile) return badRequest("`profile` query parameter is required");
  if (!lang) return badRequest("`lang` query parameter is required");
  const format = requestedFormat(params, request.headers.get("accept"));
  if (typeof format !== "string") {
    return badRequest(
      `unknown \`format\` \`${format.invalid}\` — \`html\`, \`text\` or \`json\``,
    );
  }
  const at = params.get("at") ?? params.get("asof");
  const atSecs = at ? Math.floor(Date.parse(at) / 1000) : Math.floor(Date.now() / 1000);

  const passport = await loadPassport(env, passportId);
  if (!passport.ok) return passport.response;
  const lens = await loadLens(env, profile);
  if (!lens.ok) return lens.response;

  const item = JSON.parse(lens.text) as {
    manifest?: {
      presentation?: Record<string, unknown>;
    };
  };
  const presentation = item.manifest?.presentation;
  if (!presentation) {
    return badRequest(
      `profile \`${profile}\` carries no presentation binding — \`/render\` needs one; \`/view\` serves this profile`,
    );
  }

  const minted = project(passport.text, lens.text, atSecs, "anonymous");
  if (!minted.ok) return stamped(502, { error: minted.error });
  const viewDoc = minted.view as Record<string, unknown>;
  const doc = buildRenderDocument(viewDoc, presentation, lang, lens.source, passport.fromFixtures);
  if (format === "html") {
    return new Response(htmlDocument(doc), {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8", "x-as-of": asOfNow() },
    });
  }
  if (format === "text") {
    return new Response(textDocument(doc), {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "x-as-of": asOfNow() },
    });
  }
  return stamped(200, doc);
}

// The requested output format: the explicit `format` parameter first,
// else the Accept header's preference (the native html.rs semantics).
function requestedFormat(
  params: URLSearchParams,
  accept: string | null,
): "html" | "text" | "json" | { invalid: string } {
  const explicit = params.get("format")?.trim();
  if (explicit === "html" || explicit === "text" || explicit === "json") return explicit;
  if (explicit) return { invalid: explicit };
  const first = (accept ?? "")
    .split(",")[0]
    ?.split(";")[0]
    ?.trim()
    .toLowerCase();
  if (first === "text/html" || first === "application/xhtml+xml") return "html";
  if (first === "text/plain") return "text";
  return "json";
}

interface FormattingRules {
  unit_position: string;
  decimal_digits: number;
  fallback_lang: string;
}

// Build the render document from the projected view (the same
// selection, one presentation): sections from the lens's presentation
// binding, labels per the language chain, the exact value beside the
// formatted one, gaps stated with their reason — the native render.rs
// document, derived honestly from the view the boundary computed.
function buildRenderDocument(
  viewDoc: Record<string, unknown>,
  presentation: Record<string, unknown>,
  lang: string,
  lensSource: string,
  passportFromFixtures: boolean,
): Record<string, unknown> {
  const rules = (presentation.formatting ?? {}) as Partial<FormattingRules>;
  const formatting: FormattingRules = {
    unit_position: rules.unit_position ?? "suffix",
    decimal_digits: typeof rules.decimal_digits === "number" ? rules.decimal_digits : 1,
    fallback_lang: rules.fallback_lang ?? "en",
  };
  const selectedBy = new Map<string, Record<string, unknown>>();
  for (const entry of (viewDoc.selected as Record<string, unknown>[] | undefined) ?? []) {
    selectedBy.set(entry.element as string, entry);
  }
  const missingBy = new Map<string, Record<string, unknown>>();
  const coverage = (viewDoc.coverage ?? {}) as Record<string, unknown>;
  for (const entry of (coverage.missing as Record<string, unknown>[] | undefined) ?? []) {
    missingBy.set(entry.element as string, entry);
  }

  const profileBlock = (viewDoc.profile ?? {}) as Record<string, unknown>;
  const passportBlock = (viewDoc.passport ?? {}) as Record<string, unknown>;
  const sourceLink = `/view?passport=${passportBlock.id ?? ""}&profile=${profileBlock.id ?? ""}&at=${viewDoc.as_of ?? ""}`;

  const sections = ((presentation.sections as Record<string, unknown>[] | undefined) ?? []).map(
    (section) => {
      const sectionId = String(section.id ?? "");
      const [label, labelLang] = labelFor(
        (section.labels ?? {}) as Record<string, string>,
        lang,
        formatting.fallback_lang,
        sectionId,
      );
      const elements = (section.elements as Record<string, unknown>[] | undefined) ?? [];
      return {
        id: sectionId,
        label,
        label_lang: labelLang,
        items: elements.map((element) => {
          const elementRef = String(element.element ?? "");
          const [itemLabel, itemLang] = labelFor(
            (element.labels ?? {}) as Record<string, string>,
            lang,
            formatting.fallback_lang,
            elementRef,
          );
          const item: Record<string, unknown> = {
            element: elementRef,
            label: itemLabel,
            label_lang: itemLang,
            source: { view: sourceLink },
          };
          const selected = selectedBy.get(elementRef);
          const missing = missingBy.get(elementRef);
          if (selected) {
            const unit = selected.declared_unit;
            item["value"] = selected.value;
            item["kind"] = selected.kind;
            if (unit !== undefined) item["unit"] = unit;
            item["formatted"] = formatValue(
              selected.value,
              String(selected.kind ?? "str"),
              typeof unit === "string" ? unit : undefined,
              formatting,
            );
            item["sourced"] = selected.sourced;
            item["trust"] = selected.trust;
            item["status"] = "present";
          } else if (missing) {
            item["status"] = "missing";
            for (const key of ["reason", "floor", "detail"]) {
              if (missing[key] !== undefined) item[key] = missing[key];
            }
          } else {
            item["status"] = "missing";
            item["reason"] = "not-selected";
            item["detail"] =
              "the element resolved to neither a selected value nor a reported gap";
          }
          return item;
        }),
      };
    },
  );

  const metadata: Record<string, unknown> = {
    template_ref: presentation.template_ref ?? null,
    lang,
    fallback_lang: formatting.fallback_lang,
    formatting_rules: formatting,
    as_of: viewDoc.as_of ?? null,
    profile: {
      id: profileBlock.id ?? null,
      version: profileBlock.version ?? null,
      source: lensSource,
    },
  };
  const renderedPassport: Record<string, unknown> = {
    id: passportBlock.id ?? null,
    product_id: passportBlock.product_id ?? null,
    capability: passportBlock.capability ?? null,
    status: passportBlock.status ?? null,
  };
  if (passportBlock.log_head !== undefined) {
    renderedPassport["log_head"] = passportBlock.log_head;
  }
  renderedPassport["source"] = passportFromFixtures ? "fixtures" : lensSource;

  return {
    service: "unidpp-projector",
    render_metadata: metadata,
    passport: renderedPassport,
    sections,
    coverage,
    trust: viewDoc.trust ?? {},
  };
}

// The label for one language, with the missing-label fallback chain:
// requested language → the rules' fallback language → the first label
// in language-tag order → the element (or section) id itself. Returns
// the label and the language tag that served it (null on the last
// resort — the id is not a translation).
function labelFor(
  labels: Record<string, string>,
  lang: string,
  fallbackLang: string,
  fallbackText: string,
): [string, string | null] {
  if (labels[lang] !== undefined) return [labels[lang], lang];
  if (labels[fallbackLang] !== undefined) return [labels[fallbackLang], fallbackLang];
  for (const tag of Object.keys(labels).sort()) {
    return [labels[tag], tag];
  }
  return [fallbackText, null];
}

// Display-only rounding of an exact decimal string: half-up at
// `digits`, trailing zeros stripped — the exact value always travels
// beside it in `value`.
function roundDecimal(value: string, digits: number): string {
  const negative = value.startsWith("-");
  const body = negative ? value.slice(1) : value;
  const [intPartRaw, fracRaw = ""] = body.split(".");
  const intPart = intPartRaw || "0";
  let frac = fracRaw;
  let intResult = intPart;
  if (frac.length > digits) {
    const keep = frac.slice(0, digits);
    const bump = frac[digits] >= "5" ? 1n : 0n;
    const width = intPart.length + digits;
    const text = (BigInt(intPart + keep) + bump).toString().padStart(width, "0");
    intResult = text.slice(0, text.length - digits) || "0";
    frac = text.slice(text.length - digits);
  }
  frac = frac.replace(/0+$/, "");
  const rounded = frac ? `${intResult}.${frac}` : intResult;
  return negative && rounded !== "0" ? `-${rounded}` : rounded;
}

// The display string of one fact value under the formatting rules.
function formatValue(
  value: unknown,
  kind: string,
  unit: string | undefined,
  rules: FormattingRules,
): string {
  const body =
    kind === "num"
      ? roundDecimal(String(value), rules.decimal_digits)
      : kind === "bool"
        ? value
          ? "true"
          : "false"
        : kind === "list"
          ? (value as string[]).join(", ")
          : String(value);
  return unit && rules.unit_position === "suffix" ? `${body} ${unit}` : body;
}

// ---------------------------------------------------------------------------
// The consumer serializations (the native html.rs): the standalone
// page and the speakable text, both built from the render document —
// one presentation computation, never per-template forks. Every
// string is HTML-escaped; the page carries no client-side script.
// ---------------------------------------------------------------------------

const esc = (text: string): string =>
  text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const strOf = (value: Record<string, unknown> | undefined, path: string[]): string | undefined => {
  let current: unknown = value;
  for (const key of path) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : undefined;
};

// The newest `sourced.occurred_at` across presented items — RFC 3339
// `Z` strings sort lexicographically.
function newestRecordedAt(render: Record<string, unknown>): string | undefined {
  const sections = render.sections as Record<string, unknown>[] | undefined;
  let newest: string | undefined;
  for (const item of (sections ?? []).flatMap(
    (s) => (s.items as Record<string, unknown>[] | undefined) ?? [],
  )) {
    if (item.status !== "present") continue;
    const occurredAt = strOf(item, ["sourced", "occurred_at"]);
    if (occurredAt !== undefined && (newest === undefined || occurredAt > newest)) {
      newest = occurredAt;
    }
  }
  return newest;
}

// Serialize a render document to a standalone HTML page (no external
// assets — the page is standalone by construction).
function htmlDocument(render: Record<string, unknown>): string {
  const lang = strOf(render, ["render_metadata", "lang"]) ?? "en";
  const product = strOf(render, ["passport", "product_id"]) ?? "";
  const title = product === "" ? "UniDPP" : `${product} — UniDPP`;
  const style =
    "body{font-family:system-ui,sans-serif;margin:0 auto;max-width:640px;" +
    "padding:1rem;color:#1a1a1a;background:#fafafa}" +
    ".card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem}" +
    "h1{font-size:1.25rem;margin:0 0 .5rem}" +
    "h2{font-size:1.05rem;margin:0 0 .5rem}" +
    ".meta,.asof{color:#666;font-size:.8rem;margin:.25rem 0}" +
    "section{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem}" +
    ".item{display:flex;justify-content:space-between;gap:1rem;padding:.4rem 0;border-bottom:1px solid #f0f0f0}" +
    ".item:last-child{border-bottom:none}" +
    ".label{color:#555}" +
    ".value{text-align:right;font-weight:500}" +
    ".gap .value{color:#b00;font-weight:400}" +
    ".notice{color:#555;font-size:.85rem;padding:0 .25rem}" +
    ".coverage{color:#555;font-size:.85rem;padding:.5rem .25rem}" +
    ".gaps{margin:.25rem 0;padding-left:1.25rem}";

  let out = "";
  out += "<!DOCTYPE html>\n";
  out += `<html lang="${esc(lang)}">`;
  out += "\n<head>\n<meta charset=\"utf-8\">\n";
  out += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  out += `<title>${esc(title)}</title>\n`;
  out += `<style>${style}</style>\n</head>\n<body>\n`;

  out += "<header class=\"card\">\n<h1>";
  out += esc(product);
  out += "</h1>\n<p class=\"meta\">";
  out += esc(
    `passport ${strOf(render, ["passport", "id"]) ?? ""} · capability ${strOf(render, ["passport", "capability"]) ?? ""} · status ${strOf(render, ["passport", "status"]) ?? ""}`,
  );
  out += "</p>\n</header>\n";

  const sections = (render.sections as Record<string, unknown>[] | undefined) ?? [];
  for (const section of sections) {
    out += `<section id="${esc(strOf(section, ["id"]) ?? "")}">\n<h2>${esc(strOf(section, ["label"]) ?? "")}</h2>\n`;
    for (const item of (section.items as Record<string, unknown>[] | undefined) ?? []) {
      const label = strOf(item, ["label"]) ?? "";
      const status = strOf(item, ["status"]) ?? "";
      const trust = strOf(item, ["trust"]) ?? "";
      let className = "item";
      if (status === "missing") className += " gap";
      if (trust !== "") className += ` trust-${trust}`;
      const body =
        status === "present"
          ? strOf(item, ["formatted"]) ?? ""
          : `not shown — ${strOf(item, ["detail"]) ?? "not provided"}`;
      out += `<div class="${className}"><span class="label">${esc(label)}</span><span class="value">${esc(body)}</span></div>\n`;
    }
    out += "</section>\n";
  }

  const newest = newestRecordedAt(render);
  if (newest !== undefined) {
    out += `<p class="notice">${esc(`The most recent information on this page was recorded on ${newest}.`)}</p>\n`;
  }

  const coverage = render.coverage as Record<string, unknown> | undefined;
  const required =
    typeof coverage?.elements_required === "number" ? coverage.elements_required : undefined;
  const presentCount =
    typeof coverage?.elements_present === "number" ? coverage.elements_present : undefined;
  const complete = coverage?.complete === true;
  if (required !== undefined && presentCount !== undefined) {
    out += "<footer class=\"coverage\">\n<h2>Coverage</h2>\n<p>";
    out += esc(
      `${presentCount} of ${required} elements presented — ${complete ? "complete" : "incomplete"}.`,
    );
    out += "</p>\n";
    const missing = (coverage?.missing as Record<string, unknown>[] | undefined) ?? [];
    if (missing.length > 0) {
      out += "<ul class=\"gaps\">\n";
      for (const gap of missing) {
        out += `<li>${esc(strOf(gap, ["element"]) ?? "")} — ${esc(strOf(gap, ["detail"]) ?? "not provided")}</li>\n`;
      }
      out += "</ul>\n";
    }
    const asOf = strOf(render, ["render_metadata", "as_of"]) ?? "";
    const profile = strOf(render, ["render_metadata", "profile", "id"]) ?? "";
    out += `<p class="asof">${esc(`Rendered as of ${asOf} · profile ${profile}`)}</p>\n`;
    out += "</footer>\n";
  }

  out += "</body>\n</html>\n";
  return out;
}

// The plain-text serialization: the same presentation as speakable
// text (the TTS substrate). Plain sentences, no markup: every gap is
// spoken, not hidden.
function textDocument(render: Record<string, unknown>): string {
  let out = "";
  const product = strOf(render, ["passport", "product_id"]) ?? "";
  if (product !== "") out += `${product}.\n`;
  const sections = (render.sections as Record<string, unknown>[] | undefined) ?? [];
  for (const section of sections) {
    const label = strOf(section, ["label"]) ?? "";
    if (label !== "") out += `\n${label}.\n`;
    for (const item of (section.items as Record<string, unknown>[] | undefined) ?? []) {
      const itemLabel = strOf(item, ["label"]) ?? "";
      const status = strOf(item, ["status"]) ?? "";
      const body =
        status === "present"
          ? strOf(item, ["formatted"]) ?? ""
          : `not shown — ${strOf(item, ["detail"]) ?? "not provided"}`;
      if (itemLabel !== "") out += `${itemLabel}: ${body}.\n`;
    }
  }
  const newest = newestRecordedAt(render);
  if (newest !== undefined) {
    out += `\nThe most recent information on this page was recorded on ${newest}.\n`;
  }
  const coverage = render.coverage as Record<string, unknown> | undefined;
  const required =
    typeof coverage?.elements_required === "number" ? coverage.elements_required : undefined;
  const presentCount =
    typeof coverage?.elements_present === "number" ? coverage.elements_present : undefined;
  const complete = coverage?.complete === true;
  if (required !== undefined && presentCount !== undefined) {
    out += `Coverage: ${presentCount} of ${required} elements presented, ${complete ? "complete" : "incomplete"}.`;
  }
  return out;
}

// The module root (GET /views): the discovery document the native
// projector serves at its bare prefix — the view and render query
// forms, the as-of semantics, the coverage honesty, the render
// metadata shape, the selection gates and the sources doctrine.
export function discovery(_request: Request, _options: { tenant?: string } = {}): Response {
  return stamped(200, {
    service: "unidpp-projector",
    version: "0.1.0",
    build_id: "dev",
    description:
      "UniDPP lens projection service: render a passport under a registered profile (view + coverage report) — the EU/JP two-lens moment as a service",
    endpoints: {
      view: "GET /view?passport=<passport-id>&profile=<profile-item>&actor=<role>[&at=<RFC3339>]",
      render:
        "GET /render?passport=<passport-id>&profile=<profile-item>&lang=<tag>[&at=<RFC3339>][&format=html|text|json] — JSON by default; Accept: text/html or text/plain (or the explicit format parameter, which outranks the header) serves the same render as a standalone consumer page (HTML) or as speakable text (the TTS substrate)",
      health: "GET /healthz",
    },
    view_contract: {
      profile: {
        id: "profile item id",
        version: "manifest version pin",
        axes: "...",
        applies: "trigger + effective window at the as-of instant",
        satisfiable: "capability floor vs subject",
        source: "registry | fixtures | unreachable",
      },
      selected: [
        {
          element: "register/item@version",
          value: "from the passport twin state",
          sourced: { seq: 0, occurred_at: "...", actor_role: "...", actor_id: "..." },
          trust: "I9 marker of the sourcing event",
        },
      ],
      transformed: [
        {
          id: "...",
          kind: "unit-conversion | classification | primmel | aggregation | localization-mapping",
          input: "...",
          output: "...",
          trust: "marker of the input",
          status: "computed | failed | missing-inputs | missing-children | unmapped",
        },
      ],
      coverage: {
        elements_required: 0,
        elements_present: 0,
        missing: [
          { element: "...", reason: "absent-as-of | below-trust-floor | capability-gate" },
        ],
        complete: false,
        ratio: 1.0,
      },
      as_of: "the projection instant (?at= or now)",
      trust: { "<element>": "<marker>", "…": "marker per selected element" },
    },
    selection_gates: [
      "capability-gate (subject class vs binding floor)",
      "presence (source fact on the twin state as-of)",
      "below-trust-floor (sourcing event marker vs binding floor)",
    ],
    sources: {
      passports:
        "unidpp/passport@1 documents from UNIDPP_PROJECTOR_PASSPORTS_DIR, else the built-in two-lens fixture",
      children:
        "child passports of the traversal set (derived-issuance/combine inputs, replacements) from the same store or fixtures; aggregation transforms roll up over them and commit the input set's canonical traversal-set root (unidpp-transform's Merkle rollup definition)",
      rollup:
        "signed roll-up attestations over the committed traversal set (subject = the parent passport, method_ref = the binding's method citation) when UNIDPP_PROJECTOR_ROLLUP_SEED + UNIDPP_PROJECTOR_ROLLUP_ATTESTER arm the projector's key; the field is absent otherwise, never a placeholder",
      profiles:
        "unidpp-registry profile items at UNIDPP_REGISTRY_URL (point-in-time with at=), else built-in EU/JP fixtures",
      units:
        "registry units subregister identity (ISO 80000 citation chain); conversions are exact through the local ISO 80000 seed",
      primmel:
        ".prml rule packages from UNIDPP_PROJECTOR_PRIMMEL_DIR (operator pin), else the registry transform subregister, else built-in fixtures; each evaluated rule carries its clause_urn (the legal paragraph it implements)",
      mappings:
        "code-list mapping items (class transform) from the registry transform subregister, else built-in fixtures (EU A-E class <-> JP star display); unmapped values emit the explicit `unmapped` output",
    },
    render_contract: {
      render_metadata: {
        template_ref: "the presentation binding's template",
        lang: "the requested language tag",
        fallback_lang: "served when the requested language has no label",
        formatting_rules: {
          unit_position: "suffix | none",
          decimal_digits: 1,
          fallback_lang: "en",
        },
        as_of: "the render instant",
        profile: { id: "...", version: "...", source: "registry | fixtures | unreachable" },
      },
      sections: [
        {
          id: "product | repair | recycling | ...",
          label: "localized section title",
          label_lang: "the language that served the label",
          items: [
            {
              element: "register/item@version",
              label: "localized element label",
              value: "exact value",
              formatted: "display string with unit and digits",
              source: { view: "/view?..." },
            },
          ],
        },
      ],
      coverage: "the same coverage report shape as the view",
    },
    as_of: { query_parameter: "at", response_header: "x-as-of" },
    auth: "none (read-only service; the actor parameter is recorded, not authenticated)",
  });
}
