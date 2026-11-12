// The class designer (R10 G1): the console surface over the class
// descriptor and the instance intake. The author composes the
// descriptor's manifest, validates worked instances against the
// draft with the same checks intake will run, and signs and submits
// the descriptor into the estate's own register. The signature is
// real: the console signs the canonical descriptor body through the
// wasm boundary in the profile domain (the descriptor registers
// under the profile's signed-form discipline), with the deployment's
// designer seed, degrading to the deterministic dev seed exactly as
// the estate's other operators degrade.

import {
  descriptorManifestErrors,
  descriptorSignatureErrors,
  instanceAgainstSpecs,
  parseFeatureSpecs,
  type FeatureSpec,
} from "./registry-do";
import { evalRule, parseRule, ruleDescriptorErrors } from "./rules";
import { workerCore } from "./mount";
import type { DoNamespace } from "./views";
import type { Item } from "./registry-do";

export interface DesignerEnv {
  REGISTRY?: DoNamespace;
  UNIDPP_DESIGNER_SIGN_SEED?: string;
}

const ISSUER_CLASSES = ["law", "treaty", "consensus", "declaration", "attestation"];

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
main{padding:1rem 1.5rem;max-width:64rem} h1{font-size:1.3rem}
label{display:block;margin-top:0.8rem;font-weight:bold}
input,textarea,select{font:inherit;width:100%;box-sizing:border-box}
textarea{min-height:8rem}
.row{display:flex;gap:1rem}.row>div{flex:1}
.pass{color:#1e8449}.fail{color:#b03a2e}
pre{background:#f4f6f7;padding:0.6rem;overflow-x:auto}
button{font:inherit;margin-top:1rem;margin-right:0.5rem}
</style></head><body><main>
<h1>${esc(title)}</h1>
${body}
</main></body></html>`;

const htmlResponse = (body: string): Response =>
  new Response(body, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });

// The canonical body the signature covers: the manifest without the
// signature slot, stable-key serialized (the discovery descriptors'
// discipline).
function canonicalBody(manifest: Record<string, unknown>): string {
  const stable = (value: unknown): string => {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
    const keys = Object.keys(value as Record<string, unknown>).sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${stable((value as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  };
  const rest = { ...manifest };
  delete rest.signature;
  return stable(rest);
}

function seedBytes(core: ReturnType<typeof workerCore>, envSeed: string | undefined): Uint8Array {
  const unhex = (hex: string): Uint8Array =>
    new Uint8Array((hex.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) return unhex(envSeed.trim());
  const digestPtr = core.unidpp_alloc(32);
  const text = new TextEncoder().encode("UNIDPP-CONSOLE/DESIGNER-SEED");
  const textPtr = core.unidpp_alloc(text.length);
  new Uint8Array(core.memory.buffer, textPtr, text.length).set(text);
  core.unidpp_sha256(textPtr, text.length, digestPtr);
  const digest = new Uint8Array(core.memory.buffer, digestPtr, 32).slice();
  core.unidpp_free(textPtr, text.length);
  core.unidpp_free(digestPtr, 32);
  return digest;
}

function sign(core: ReturnType<typeof workerCore>, seed: Uint8Array, payload: string): {
  signature: string;
  keyId: string;
} {
  const put = (bytes: Uint8Array): { ptr: number; len: number } => {
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const seedPart = put(seed);
  const domain = put(new TextEncoder().encode("profile"));
  const body = put(new TextEncoder().encode(payload));
  const sigPtr = core.unidpp_alloc(64);
  const rc = core.unidpp_sign_raw(seedPart.ptr, domain.ptr, domain.len, body.ptr, body.len, sigPtr);
  const signature = Array.from(new Uint8Array(core.memory.buffer, sigPtr, 64).slice())
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const idPtr = core.unidpp_alloc(64);
  const idLen = core.unidpp_head_key_id(seedPart.ptr, idPtr);
  const keyId = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, idPtr, Math.max(idLen, 0)).slice(),
  );
  [seedPart, domain, body].forEach((part, i) =>
    core.unidpp_free(part.ptr, [seed.length, domain.len, body.len][i]),
  );
  core.unidpp_free(sigPtr, 64);
  core.unidpp_free(idPtr, 64);
  if (rc !== 0) throw new Error(`the signature failed (${rc})`);
  return { signature, keyId };
}

interface Draft {
  classId: string;
  title: string;
  version: string;
  manifest: Record<string, unknown>;
}

// The draft from the form: the descriptor's manifest as the author
// states it (features, capability_classes, rule_references, issuer
// fields), assembled server-side from named fields plus the
// features JSON document.
function draftOf(form: FormData): { draft?: Draft; errors: string[] } {
  const errors: string[] = [];
  const classId = String(form.get("class_id") ?? "").trim();
  const title = String(form.get("definition") ?? "").trim();
  const version = String(form.get("version") ?? "").trim() || "1.0.0";
  if (!classId) errors.push("class_id: the identifier names the class");
  if (!title) errors.push("definition: the class states its definition");
  let features: unknown;
  const featuresText = String(form.get("features") ?? "").trim();
  if (featuresText) {
    try {
      features = JSON.parse(featuresText);
    } catch (e) {
      errors.push(`features: the feature specs are not JSON (${(e as Error).message})`);
    }
  }
  const capabilityClasses = String(form.get("capability_classes") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const ruleReferences = String(form.get("rule_references") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  let rules: unknown;
  const rulesText = String(form.get("rules") ?? "").trim();
  if (rulesText) {
    try {
      rules = JSON.parse(rulesText);
    } catch (e) {
      errors.push(`rules: the rule declarations are not JSON (${(e as Error).message})`);
    }
  }
  const issuerClass = String(form.get("issuer_class") ?? "").trim();
  const issuer = String(form.get("issuer") ?? "").trim();
  if (errors.length > 0) return { errors };
  const manifest: Record<string, unknown> = {
    version,
    class_id: classId,
    issuer_class: issuerClass,
    issuer,
    features: features ?? [],
    capability_classes: capabilityClasses,
    rule_references: ruleReferences,
    rules: rules ?? [],
  };
  return { draft: { classId, title, version, manifest }, errors };
}

// The draft against its own shape (the checks intake will run),
// plus each worked instance.
function validateDraft(
  draft: Draft,
  instances: Record<string, unknown>[],
  resolveUnit: (identifier: string) => Item | undefined,
  checkUnits: boolean,
): {
  descriptor: string[];
  instances: { index: number; errors: string[] }[];
} {
  // The draft's own shape: the signed form's issuer fields (the
  // signature slot itself is the console's job at submit — the page
  // states it), plus the manifest checks intake will run.
  const descriptor = [
    ...descriptorSignatureErrors(draft.manifest).filter(
      (e) => !e.startsWith("manifest.signature"),
    ),
    ...descriptorManifestErrors(draft.classId, draft.manifest),
  ];
  const parsed = parseFeatureSpecs(draft.manifest);
  const specs = parsed.ok ? parsed.specs : [];
  const declaredRules = new Map<string, string>();
  const declared = draft.manifest["rules"];
  if (Array.isArray(declared)) {
    for (const rule of declared as Record<string, unknown>[]) {
      const id = typeof rule["id"] === "string" ? rule["id"] : "";
      const expression = typeof rule["expr"] === "string" ? rule["expr"] : "";
      if (id) declaredRules.set(id, expression);
    }
  }
  const results = instances.map((features, index) => {
    const errors = instanceAgainstSpecs(
      draft.classId,
      specs,
      features,
      { item: resolveUnit },
      checkUnits,
    );
    for (const reference of (draft.manifest["rule_references"] as string[] | undefined) ?? []) {
      const expression = declaredRules.get(reference);
      if (!expression) continue;
      const parsed = parseRule(expression);
      if (parsed.ok && !evalRule(parsed.expr, features)) {
        errors.push(
          `manifest.rule_references.${reference}: the rule \`${reference}\` of the class \`${draft.classId}\` is not satisfied: ${expression}`,
        );
      }
    }
    return { index, errors };
  });
  return { descriptor, instances: results };
}

function renderDesigner(result?: {
  draft?: Draft;
  descriptor: string[];
  instances: { index: number; errors: string[] }[];
  submitted?: { ok: boolean; message: string };
}): string {
  const form = `
<form method="post" action="/console/designer">
<div class="row">
  <div><label>class_id (the identifier names the class)</label><input name="class_id" value="${esc(result?.draft?.classId ?? "")}" placeholder="tyre-e8"></div>
  <div><label>version</label><input name="version" value="${esc(result?.draft?.version ?? "1.0.0")}"></div>
</div>
<label>definition</label><input name="definition" value="${esc(result?.draft?.title ?? "")}" placeholder="The E8 tyre class">
<div class="row">
  <div><label>issuer_class (the five authority classes)</label>
  <select name="issuer_class">${ISSUER_CLASSES.map((c) => `<option${result?.draft?.manifest["issuer_class"] === c ? " selected" : ""}>${c}</option>`).join("")}</select></div>
  <div><label>issuer (the signer of record)</label><input name="issuer" value="${esc(String(result?.draft?.manifest["issuer"] ?? ""))}" placeholder="urn:unidpp:actor:consortium"></div>
</div>
<label>features (the feature specs, as a JSON array)</label>
<textarea name="features" placeholder='[{"path":"tyre.pressure-bar","kind":"decimal","required":true,"unit":"bar"}]'>${esc(
    result?.draft?.manifest["features"] ? JSON.stringify(result.draft.manifest["features"], null, 2) : "",
  )}</textarea>
<label>rules (the rule declarations, as a JSON array of {id, expr})</label>
<textarea name="rules" placeholder='[{"id":"rule.pressure-range","expr":"tyre.pressure-bar >= 1.0 and tyre.pressure-bar <= 4.5"}]'>${esc(
    result?.draft?.manifest["rules"] ? JSON.stringify(result.draft.manifest["rules"], null, 2) : "",
  )}</textarea>
<div class="row">
  <div><label>capability_classes (comma-separated S0–S3 tokens)</label><input name="capability_classes" value="${esc(
    (result?.draft?.manifest["capability_classes"] as string[] | undefined ?? []).join(", "),
  )}" placeholder="silent, logged-contact"></div>
  <div><label>rule_references (comma-separated rule ids)</label><input name="rule_references" value="${esc(
    (result?.draft?.manifest["rule_references"] as string[] | undefined ?? []).join(", "),
  )}" placeholder="rule.pressure-range"></div>
</div>
<label>worked instances (a JSON array of twin-fact maps)</label>
<textarea name="instances" placeholder='[{"tyre.pressure-bar":2.3,"tyre.season":"winter"}]'></textarea>
<button type="submit" name="action" value="validate">validate the draft</button>
<button type="submit" name="action" value="submit">sign and submit</button>
</form>`;

  const sections: string[] = [form];
  if (result) {
    const descriptorOk = result.descriptor.length === 0;
    sections.push(
      `<h2>The draft's own shape</h2>${
        descriptorOk
          ? `<p class="pass">The draft carries the signed form and a well-shaped manifest.</p>`
          : `<p class="fail">The draft refuses:</p><ul>${result.descriptor
              .map((e) => `<li class="fail">${esc(e)}</li>`)
              .join("")}</ul>`
      }`,
    );
    if (result.instances.length > 0) {
      sections.push(
        `<h2>The worked instances</h2>${result.instances
          .map(({ index, errors }) =>
            errors.length === 0
              ? `<p class="pass">Instance ${index + 1}: conforms to the draft.</p>`
              : `<p class="fail">Instance ${index + 1} refuses:</p><ul>${errors
                  .map((e) => `<li class="fail">${esc(e)}</li>`)
                  .join("")}</ul>`,
          )
          .join("")}`,
      );
    }
    if (result.submitted) {
      sections.push(
        result.submitted.ok
          ? `<p class="pass">${esc(result.submitted.message)}</p>`
          : `<p class="fail">${esc(result.submitted.message)}</p>`,
      );
    }
  }
  return page("The class designer", sections.join("\n"));
}


async function unitResolver(
  env: DesignerEnv,
): Promise<(identifier: string) => Item | undefined> {
  if (!env.REGISTRY) return () => undefined;
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName("estate"));
  const cache = new Map<string, Item | undefined>();
  return (identifier: string) => {
    if (cache.has(identifier)) return cache.get(identifier);
    void stub
      .fetch(new Request(`https://do.internal/items/${encodeURIComponent(identifier)}`))
      .then(async (response) => {
        const body = (await response.json().catch(() => ({}))) as { item_class?: string };
        cache.set(
          identifier,
          response.status === 200 ? ({ item_class: body.item_class ?? "" } as Item) : undefined,
        );
      })
      .catch(() => cache.set(identifier, undefined));
    return cache.get(identifier);
  };
}

export async function designer(
  request: Request,
  env: DesignerEnv,
): Promise<Response> {
  if (request.method === "GET") return htmlResponse(renderDesigner());
  let form: FormData;
  try {
    form = (await request.formData()) as FormData;
  } catch {
    return htmlResponse(renderDesigner());
  }
  const action = String(form.get("action") ?? "validate");
  const { draft, errors } = draftOf(form);
  if (!draft) {
    return htmlResponse(
      renderDesigner({
        descriptor: errors,
        instances: [],
      }),
    );
  }
  let instances: Record<string, unknown>[] = [];
  const instancesText = String(form.get("instances") ?? "").trim();
  if (instancesText) {
    try {
      const parsed = JSON.parse(instancesText);
      instances = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      return htmlResponse(
        renderDesigner({
          draft,
          descriptor: ["worked instances: the JSON does not parse"],
          instances: [],
        }),
      );
    }
  }
  if (action === "validate") {
    const resolveUnit = await unitResolver(env);
    return htmlResponse(
      renderDesigner({ draft, ...validateDraft(draft, instances, resolveUnit, Boolean(env.REGISTRY)) }),
    );
  }
  // sign and submit: the signature covers the canonical body, the
  // register receives the assembled item through its own intake.
  const core = workerCore();
  let signatureBlock: { signature: string; keyId: string };
  try {
    const seed = seedBytes(core, env.UNIDPP_DESIGNER_SIGN_SEED);
    signatureBlock = sign(core, seed, canonicalBody(draft.manifest));
  } catch (e) {
    return htmlResponse(
      renderDesigner({
        draft,
        descriptor: [(e as Error).message],
        instances: [],
      }),
    );
  }
  const manifest = {
    ...draft.manifest,
    signature: {
      signature: signatureBlock.signature,
      suite: "ed25519",
      key_id: signatureBlock.keyId,
    },
  };
  if (!env.REGISTRY) {
    return htmlResponse(
      renderDesigner({
        draft,
        descriptor: ["the registry Durable Object is not bound"],
        instances: [],
      }),
    );
  }
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName("estate"));
  const registered = await stub.fetch(
    new Request("https://do.internal/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-registry",
        item_id: draft.classId,
        class: "class-descriptor",
        definition: draft.title,
        version: draft.version,
        manifest,
      }),
    }),
  );
  if (registered.status === 201) {
    return htmlResponse(
      renderDesigner({
        draft,
        descriptor: [],
        instances: [],
        submitted: {
          ok: true,
          message: `The class \`${draft.classId}\` is registered (signed by ${signatureBlock.keyId}); the register's discovery surfaces it.`,
        },
      }),
    );
  }
  const refusal = ((await registered.json()) as { error?: string }).error ?? "the register refused";
  return htmlResponse(
    renderDesigner({
      draft,
      descriptor: [refusal],
      instances: [],
    }),
  );
}
