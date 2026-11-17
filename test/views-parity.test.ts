// The views surface's contract-parity gates: /views/render is the
// same selection the view serves, presented per the lens's
// presentation binding (the native projector's /render) in the three
// wire formats, and GET /views serves the native's discovery
// document.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";
import { RegistryDO } from "../src/registry-do";
import { view, discovery } from "../src/views";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

// A registry lens that presents the demo passport's battery facts:
// localized sections, declared units, and an element the passport
// never provides (the stated gap).
const LENS_ITEM = {
  register_id: "unidpp-registry",
  item_id: "urn:unidpp:profile:render-lens",
  class: "profile",
  definition: "The render lens",
  version: "1.0.0",
  manifest: {
    version: "1.0.0",
    profile: {
      id: "urn:unidpp:profile:render-lens",
      axes: { jurisdiction: "EU", sector: "batteries", characteristic: "battery-passport" },
      trigger: "Any",
      min_capability: "silent",
      freshness: "Static",
      effective: { from: "2026-01-01T00:00:00Z" },
      data_points: [
        { register: "unidpp", item: "product-id", version: "1.0.0" },
        { register: "unidpp", item: "absent-fact", version: "1.0.0" },
      ],
      crypto_suites: ["ecdsa-p256"],
      confidential: false,
      resolution: "public",
      edge_visibility: "public",
      traversal: "public",
    },
    bindings: [
      {
        element: "unidpp/product-id@1.0.0",
        source: "product_id",
        min_trust: "self-declared",
        min_capability: "silent",
      },
      {
        element: "unidpp/absent-fact@1.0.0",
        source: "battery.capacity-kwh",
        min_trust: "self-declared",
        min_capability: "silent",
        declared_unit: "kWh",
      },
    ],
    presentation: {
      template_ref: "urn:unidpp:template:consumer-v1",
      formatting: { unit_position: "suffix", decimal_digits: 1, fallback_lang: "en" },
      sections: [
        {
          id: "product",
          labels: { en: "Product", ja: "製品情報" },
          elements: [
            { element: "unidpp/product-id@1.0.0", labels: { en: "Product", ja: "製品" } },
            {
              element: "unidpp/absent-fact@1.0.0",
              labels: { en: "Battery capacity", ja: "電池容量" },
            },
          ],
        },
      ],
    },
  },
};

const envWith = (issuer: IssuerDO, registry: RegistryDO) => ({
  ISSUER: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: issuer.fetch.bind(issuer) }),
  },
  REGISTRY: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: registry.fetch.bind(registry) }),
  },
});

const DEMO_PASSPORT = "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345";
const CONSUMER_LENS = "urn:unidpp:profile:consumer-dpp";

describe("the /views/render surface", () => {
  it("presents a minted passport under a registry lens", async () => {
    const issuer = new IssuerDO(storage());
    const registry = new RegistryDO(storage());
    await registry.fetch(
      new Request("https://do.internal/items", {
        method: "POST",
        body: JSON.stringify(LENS_ITEM),
      }),
    );
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({ identity: "https://product.example.org/render-1" }),
      }),
    );
    expect(minted.status).toBe(201);
    const passport = (await minted.json()) as { passport_id: string };

    const response = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(passport.passport_id)}&profile=urn:unidpp:profile:render-lens&lang=en`,
      ),
      envWith(issuer, registry),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = (await response.json()) as Record<string, unknown>;
    expect(doc.service).toBe("unidpp-projector");

    const metadata = doc.render_metadata as Record<string, unknown>;
    expect(metadata.lang).toBe("en");
    expect(metadata.fallback_lang).toBe("en");
    expect(metadata.template_ref).toBe("urn:unidpp:template:consumer-v1");
    expect(metadata.formatting_rules).toEqual({
      unit_position: "suffix",
      decimal_digits: 1,
      fallback_lang: "en",
    });
    expect((metadata.profile as Record<string, unknown>).id).toBe(
      "urn:unidpp:profile:render-lens",
    );
    expect((metadata.profile as Record<string, unknown>).source).toBe("registry");
    expect(typeof metadata.as_of).toBe("string");

    const passportBlock = doc.passport as Record<string, unknown>;
    expect(passportBlock.id).toBe(passport.passport_id);
    expect(passportBlock.capability).toBe("silent");
    expect(passportBlock.source).toBe("registry");

    // The sections carry labels; the minted passport has no sealed
    // events yet, so every element states its absence honestly.
    const sections = doc.sections as {
      id: string;
      label: string;
      label_lang: string;
      items: Record<string, unknown>[];
    }[];
    expect(sections).toHaveLength(1);
    expect(sections[0].id).toBe("product");
    expect(sections[0].label).toBe("Product");
    expect(sections[0].label_lang).toBe("en");
    for (const item of sections[0].items) {
      expect(item.status).toBe("missing");
      expect(item.reason).toBe("absent-as-of");
      expect(item.detail).toBe("no event wrote this fact at or before the as-of instant");
      expect((item.source as Record<string, string>).view).toContain("/view?passport=");
      expect((item.source as Record<string, string>).view).toContain(
        "profile=urn:unidpp:profile:render-lens",
      );
    }

    // The same coverage report shape as the view.
    const coverage = doc.coverage as Record<string, unknown>;
    expect(coverage.elements_required).toBe(2);
    expect(coverage.elements_present).toBe(0);
    expect(coverage.complete).toBe(false);
    expect(typeof coverage.ratio).toBe("number");
    expect(doc.trust).toEqual({});
  });

  it("renders the built-in two-lens demo through the fixture consumer lens", async () => {
    const response = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en`,
      ),
      {},
    );
    expect(response.status).toBe(200);
    const doc = (await response.json()) as Record<string, unknown>;
    expect((doc.render_metadata as Record<string, unknown>).lang).toBe("en");
    const sections = doc.sections as {
      id: string;
      label: string;
      items: Record<string, unknown>[];
    }[];
    expect(sections.map((s) => s.id)).toEqual(["product", "repair", "recycling"]);
    const items = new Map<string, Record<string, unknown>>(
      sections.flatMap((s) => s.items.map((i) => [String(i.element), i])),
    );
    // The exact value, the display rounding and the unit travel
    // together (the native render's own demo numbers).
    const capacity = items.get("ferin:eu/battery.capacity-kwh@1.0.0");
    if (capacity && capacity.status === "present") {
      expect(capacity.value).toBe("0.072");
      expect(capacity.formatted).toBe("0.1 kWh");
      expect(capacity.unit).toBe("kWh");
      expect(capacity.kind).toBe("num");
      expect((capacity.sourced as Record<string, unknown>).seq).toBeDefined();
      expect(capacity.trust).toBe("self-declared");
    }
    // The deliberately absent recycling instruction is stated.
    const instruction = items.get("ferin:eu/de.dpp.recycling-instruction@1.0.0");
    expect(instruction?.status).toBe("missing");
    expect(instruction?.reason).toBe("absent-as-of");
    const coverage = doc.coverage as {
      elements_required: number;
      elements_present: number;
      complete: boolean;
    };
    expect(coverage.elements_required).toBe(5);
    expect(coverage.complete).toBe(false);
  });

  it("falls back through the label chain per language", async () => {
    const japanese = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=ja`,
      ),
      {},
    );
    const jaDoc = (await japanese.json()) as {
      render_metadata: Record<string, unknown>;
      sections: { label: string }[];
    };
    expect(jaDoc.render_metadata.lang).toBe("ja");
    expect(jaDoc.sections[0].label).toBe("製品情報");
    // French has no labels: the fallback language serves, and the
    // render states which language did.
    const french = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=fr`,
      ),
      {},
    );
    const frDoc = (await french.json()) as {
      render_metadata: { lang: string; fallback_lang: string };
      sections: { label: string; label_lang: string | null }[];
    };
    expect(frDoc.render_metadata.lang).toBe("fr");
    expect(frDoc.render_metadata.fallback_lang).toBe("en");
    expect(frDoc.sections[0].label).toBe("Product");
    expect(frDoc.sections[0].label_lang).toBe("en");
  });

  it("serves the speakable text and the standalone page", async () => {
    const text = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en&format=text`,
      ),
      {},
    );
    expect(text.status).toBe(200);
    expect(text.headers.get("content-type")).toContain("text/plain");
    const spoken = await text.text();
    expect(spoken).toContain("Product.");
    expect(spoken).toContain("Recycling instruction: not shown — ");
    expect(spoken).toMatch(/Coverage: \d+ of 5 elements presented, incomplete\.$/);
    expect(spoken).not.toContain("<");

    const page = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en&format=html`,
      ),
      {},
    );
    expect(page.status).toBe(200);
    expect(page.headers.get("content-type")).toContain("text/html");
    const html = await page.text();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<h2>Product</h2>");
    expect(html).toContain("Coverage");
    // The explicit format outranks the Accept header.
    const override = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en&format=json`,
        { headers: { accept: "text/html" } },
      ),
      {},
    );
    expect(override.headers.get("content-type")).toContain("application/json");
    // The Accept header alone negotiates the page.
    const accepted = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en`,
        { headers: { accept: "text/html,application/xhtml+xml" } },
      ),
      {},
    );
    expect(accepted.headers.get("content-type")).toContain("text/html");
  });

  it("refuses the native's validation failures with the native's texts", async () => {
    const noLang = await view(
      new Request("https://unidpp.workers.dev/views/render?passport=p&profile=q"),
      {},
    );
    expect(noLang.status).toBe(400);
    expect(((await noLang.json()) as Record<string, unknown>).error).toBe("`lang` query parameter is required");
    const badFormat = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en&format=xml`,
      ),
      {},
    );
    expect(badFormat.status).toBe(400);
    expect(((await badFormat.json()) as Record<string, unknown>).error).toBe(
      "unknown `format` `xml` — `html`, `text` or `json`",
    );
    // The EU lens carries no presentation binding: /render refuses it.
    const noPresentation = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=${encodeURIComponent(DEMO_PASSPORT)}&profile=urn:unidpp:profile:eu-espr-electronics&lang=en`,
      ),
      {},
    );
    expect(noPresentation.status).toBe(400);
    expect(((await noPresentation.json()) as Record<string, unknown>).error).toBe(
      "profile `urn:unidpp:profile:eu-espr-electronics` carries no presentation binding — `/render` needs one; `/view` serves this profile",
    );
    const noPassport = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?passport=absent&profile=${encodeURIComponent(CONSUMER_LENS)}&lang=en`,
      ),
      {},
    );
    expect(noPassport.status).toBe(404);
    expect(((await noPassport.json()) as Record<string, unknown>).error).toBe("no passport `absent`");
  });
});

describe("the /views discovery document", () => {
  it("serves the native projector's bare-prefix answer", async () => {
    const response = await discovery(new Request("https://unidpp.workers.dev/views"));
    expect(response.status).toBe(200);
    expect(response.headers.get("x-as-of")).toBeTruthy();
    const doc = (await response.json()) as Record<string, unknown>;
    expect(doc.service).toBe("unidpp-projector");
    expect(doc.version).toBe("0.1.0");
    expect(doc.description).toContain("lens projection service");
    const endpoints = doc.endpoints as Record<string, string>;
    expect(endpoints.render).toContain("GET /render?passport=");
    expect(endpoints.view).toContain("GET /view?passport=");
    expect(doc.selection_gates).toEqual([
      "capability-gate (subject class vs binding floor)",
      "presence (source fact on the twin state as-of)",
      "below-trust-floor (sourcing event marker vs binding floor)",
    ]);
    const renderContract = doc.render_contract as Record<string, unknown>;
    expect(renderContract.coverage).toBe("the same coverage report shape as the view");
    const sources = doc.sources as Record<string, string>;
    expect(sources.mappings).toContain("unmapped");
    expect(doc.as_of).toEqual({ query_parameter: "at", response_header: "x-as-of" });
    expect(doc.auth).toContain("read-only service");
  });

  it("rides behind the estate router's module root", async () => {
    // The estate routes GET /views into this module's discovery and
    // /views/view|/views/render into view(). Both answer.
    const rendered = await view(
      new Request(
        `https://unidpp.workers.dev/views/render?${new URLSearchParams({ passport: DEMO_PASSPORT, profile: CONSUMER_LENS, lang: "en" }).toString()}`,
      ),
      {},
    );
    expect(rendered.status).toBe(200);
    const viewed = await view(
      new Request(
        `https://unidpp.workers.dev/views/view?${new URLSearchParams({ passport: DEMO_PASSPORT, profile: CONSUMER_LENS, actor: "parity" }).toString()}`,
      ),
      {},
    );
    expect(viewed.status).toBe(200);
    // The render and the view answer the same coverage.
    const renderCoverage = ((await rendered.json()) as Record<string, unknown>).coverage;
    const viewCoverage = ((await viewed.json()) as Record<string, unknown>).coverage;
    expect(renderCoverage).toEqual(viewCoverage);
  });
});
