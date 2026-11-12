// The mapping workbench (R10 G7): the console surface over the
// clause-15 mapping discipline. The author composes a mapping item
// — source, target, version, and the tiered kind (deterministic,
// correspondence, no-mapping) — and the workbench validates it
// through the wasm boundary: the canonical bytes and the digest the
// corpus pins come back for a well-formed item, with the parse
// refusal named otherwise. Two drafts compose into a chain preview
// (the first's target must be the second's source, a tier-3 hop
// refuses, the policy cap holds), and submit registers the item
// into the estate's own register under the tier duties intake
// enforces.

import { workerCore } from "./mount";
import type { DoNamespace } from "./views";

export interface WorkbenchEnv {
  REGISTRY?: DoNamespace;
}

const NOTE_CAPACITY = 1048576;

const esc = (value: unknown): string =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const page = (title: string, body: string): string => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(title)} — UniDPP console</title>
<style>
body{font-family:sans-serif;margin:0;color:#17202a}
main{padding:1rem 1.5rem;max-width:64rem} h1{font-size:1.3rem} h2{font-size:1.1rem;margin-top:1.5rem}
label{display:block;margin-top:0.8rem;font-weight:bold}
input,textarea,select{font:inherit;width:100%;box-sizing:border-box}
textarea{min-height:7rem}
.row{display:flex;gap:1rem}.row>div{flex:1}
.pass{color:#1e8449}.fail{color:#b03a2e}
pre{background:#f4f6f7;padding:0.6rem;overflow-x:auto;font-size:0.8rem}
button{font:inherit;margin-top:1rem;margin-right:0.5rem}
</style></head><body><main>
<h1>${esc(title)}</h1>
${body}
</main></body></html>`;

const htmlResponse = (body: string): Response =>
  new Response(body, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });

function takeNote(core: ReturnType<typeof workerCore>): string {
  const notePtr = core.unidpp_alloc(NOTE_CAPACITY);
  const noteLen = core.unidpp_note_take(notePtr);
  const note = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, notePtr, Math.max(noteLen, 0)).slice(),
  );
  core.unidpp_free(notePtr, NOTE_CAPACITY);
  return note;
}

function putBytes(core: ReturnType<typeof workerCore>, text: string): { ptr: number; len: number } {
  const bytes = new TextEncoder().encode(text);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

// The boundary's canonical verdict: canonical bytes + digest for a
// well-formed item, the parse refusal otherwise.
function validateBoundary(itemText: string): {
  ok: true; canonicalHex: string; digestHex: string;
} | { ok: false; error: string } {
  const core = workerCore();
  const part = putBytes(core, itemText);
  const rc = core.unidpp_mapping_validate(part.ptr, part.len);
  core.unidpp_free(part.ptr, 0);
  const note = takeNote(core);
  if (rc === 0) {
    const body = JSON.parse(note) as { canonical_hex: string; digest_hex: string };
    return { ok: true, canonicalHex: body.canonical_hex, digestHex: body.digest_hex };
  }
  return { ok: false, error: note || `the validation failed (${rc})` };
}

// The boundary's composition verdict: the chain document or the
// refusal (mismatch, tier-3 hop, over-cap).
function composeBoundary(firstText: string, secondText: string, cap: number): {
  ok: true; chain: Record<string, unknown>;
} | { ok: false; error: string } {
  const core = workerCore();
  const first = putBytes(core, firstText);
  const second = putBytes(core, secondText);
  const rc = core.unidpp_mapping_compose(
    first.ptr,
    first.len,
    second.ptr,
    second.len,
    BigInt(Math.floor(cap)),
  );
  core.unidpp_free(first.ptr, 0);
  core.unidpp_free(second.ptr, 0);
  const note = takeNote(core);
  if (rc === 0) return { ok: true, chain: JSON.parse(note) as Record<string, unknown> };
  return { ok: false, error: note || `the composition failed (${rc})` };
}

const TIER_FIELDS: Record<string, string> = {
  deterministic: "transform",
  correspondence: "scope, residual, attester",
  "no-mapping": "note",
};

function draftOf(form: FormData): { item?: Record<string, unknown>; error?: string } {
  const source = String(form.get("source") ?? "").trim();
  const target = String(form.get("target") ?? "").trim();
  const versionRaw = String(form.get("version") ?? "").trim();
  const version = Number(versionRaw || "1");
  const tier = String(form.get("tier") ?? "").trim();
  if (!source) return { error: "source: the mapping names its source item" };
  if (!target) return { error: "target: the mapping names its target item" };
  if (!Number.isInteger(version) || version < 1) {
    return { error: "version: the mapping's own version is a positive integer" };
  }
  const kind: Record<string, unknown> = { tier };
  if (tier === "deterministic") {
    kind["transform"] = String(form.get("transform") ?? "").trim();
  } else if (tier === "correspondence") {
    kind["scope"] = String(form.get("scope") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    kind["residual"] = String(form.get("residual") ?? "").trim();
    kind["attester"] = String(form.get("attester") ?? "").trim();
  } else if (tier === "no-mapping") {
    kind["note"] = String(form.get("note") ?? "").trim();
  } else {
    return { error: "tier: one of deterministic, correspondence, no-mapping" };
  }
  return { item: { source, target, version, kind } };
}

function renderWorkbench(result?: {
  item?: Record<string, unknown>;
  canonical?: { canonicalHex: string; digestHex: string };
  error?: string;
  chain?: { chain?: Record<string, unknown>; error?: string };
  submitted?: { ok: boolean; message: string };
}): string {
  const item = result?.item;
  const tier = item ? String((item["kind"] as Record<string, unknown>)["tier"] ?? "") : "";
  const form = `
<form method="post" action="/console/mappings">
<div class="row">
  <div><label>source (the source item)</label><input name="source" value="${esc(item?.["source"] ?? "")}" placeholder="urn:unidpp:elements:eu-battery@3"></div>
  <div><label>target (the target item)</label><input name="target" value="${esc(item?.["target"] ?? "")}" placeholder="urn:unidpp:elements:cn-battery@2"></div>
  <div style="max-width:8rem"><label>version</label><input name="version" value="${esc(item?.["version"] ?? "1")}"></div>
</div>
<label>tier (the discipline's three tiers)</label>
<select name="tier">
  <option value="deterministic"${tier === "deterministic" ? " selected" : ""}>deterministic — a registered transform applies</option>
  <option value="correspondence"${tier === "correspondence" ? " selected" : ""}>correspondence — scope and residual declared</option>
  <option value="no-mapping"${tier === "no-mapping" ? " selected" : ""}>no-mapping — the pair recorded, nothing inferred</option>
</select>
<label>transform (tier 1: the registered, versioned transform reference)</label>
<input name="transform" value="${esc(String((item?.["kind"] as Record<string, unknown> | undefined)?.["transform"] ?? ""))}" placeholder="urn:unidpp:transform:eu-cn-mass@4">
<div class="row">
  <div><label>scope (tier 2: comma-separated)</label><input name="scope" value="${esc(
    ((item?.["kind"] as Record<string, unknown> | undefined)?.["scope"] as string[] | undefined ?? []).join(", "),
  )}" placeholder="carbon-footprint, recycled-content"></div>
  <div><label>attester (tier 2)</label><input name="attester" value="${esc(String((item?.["kind"] as Record<string, unknown> | undefined)?.["attester"] ?? ""))}"></div>
</div>
<label>residual (tier 2: what the correspondence does not cover)</label>
<input name="residual" value="${esc(String((item?.["kind"] as Record<string, unknown> | undefined)?.["residual"] ?? ""))}">
<label>note (tier 3: why no correspondence is asserted)</label>
<input name="note" value="${esc(String((item?.["kind"] as Record<string, unknown> | undefined)?.["note"] ?? ""))}">
<label>second mapping (optional: a JSON item to compose onto this one)</label>
<textarea name="second" placeholder='{"source":"...","target":"...","version":1,"kind":{"tier":"deterministic","transform":"..."}}'></textarea>
<button type="submit" name="action" value="validate">validate and preview</button>
<button type="submit" name="action" value="submit">submit to the register</button>
</form>
<p>The tier fields this tier carries: ${esc(Object.entries(TIER_FIELDS).map(([t, f]) => `${t}: ${f}`).join(" · "))}.</p>`;

  const sections: string[] = [form];
  if (result?.error) {
    sections.push(`<p class="fail">${esc(result.error)}</p>`);
  }
  if (result?.canonical) {
    sections.push(
      `<h2>The canonical form</h2>
<p class="pass">The item is well-formed. Digest <code>${esc(result.canonical.digestHex)}</code></p>
<pre>${esc(result.canonical.canonicalHex)}</pre>`,
    );
  }
  if (result?.chain) {
    if (result.chain.error) {
      sections.push(`<p class="fail">The composition refuses: ${esc(result.chain.error)}</p>`);
    } else {
      sections.push(
        `<h2>The chain preview</h2><pre>${esc(JSON.stringify(result.chain.chain, null, 2))}</pre>`,
      );
    }
  }
  if (result?.submitted) {
    sections.push(
      result.submitted.ok
        ? `<p class="pass">${esc(result.submitted.message)}</p>`
        : `<p class="fail">${esc(result.submitted.message)}</p>`,
    );
  }
  return page("The mapping workbench", sections.join("\n"));
}

export async function workbench(request: Request, env: WorkbenchEnv): Promise<Response> {
  if (request.method === "GET") return htmlResponse(renderWorkbench());
  let form: FormData;
  try {
    form = (await request.formData()) as FormData;
  } catch {
    return htmlResponse(renderWorkbench());
  }
  const action = String(form.get("action") ?? "validate");
  const { item, error } = draftOf(form);
  if (!item) {
    return htmlResponse(renderWorkbench({ error }));
  }
  const itemText = JSON.stringify(item);
  const verdict = validateBoundary(itemText);
  if (!verdict.ok) {
    return htmlResponse(renderWorkbench({ item, error: verdict.error }));
  }
  if (action === "validate") {
    // The composition preview rides when a second mapping is stated.
    const secondText = String(form.get("second") ?? "").trim();
    let chain: { chain?: Record<string, unknown>; error?: string } | undefined;
    if (secondText) {
      const composed = composeBoundary(itemText, secondText, 5);
      chain = composed.ok ? { chain: composed.chain } : { error: composed.error };
    }
    return htmlResponse(renderWorkbench({ item, canonical: verdict, chain }));
  }
  // submit: the register receives the tier form and enforces the
  // tier duties at intake.
  if (!env.REGISTRY) {
    return htmlResponse(
      renderWorkbench({ item, canonical: verdict, error: "the registry Durable Object is not bound" }),
    );
  }
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName("estate"));
  const registered = await stub.fetch(
    new Request("https://do.internal/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: `map-${String((item["kind"] as Record<string, unknown>)["tier"])}-${item["source"]}-${item["target"]}`
          .replace(/[^a-zA-Z0-9.-]/g, "-")
          .slice(0, 200),
        class: "cross-register-mapping",
        definition: `${(item["kind"] as Record<string, unknown>)["tier"]} mapping: ${item["source"]} → ${item["target"]}`,
        version: `1.${item["version"]}.0`,
        manifest: item,
      }),
    }),
  );
  if (registered.status === 201) {
    return htmlResponse(
      renderWorkbench({
        item,
        canonical: verdict,
        submitted: {
          ok: true,
          message: `The mapping is registered (digest ${verdict.digestHex}); the register holds it at its subregister.`,
        },
      }),
    );
  }
  const refusal = ((await registered.json()) as { error?: string }).error ?? "the register refused";
  return htmlResponse(renderWorkbench({ item, canonical: verdict, error: refusal }));
}
