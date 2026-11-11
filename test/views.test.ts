// The views gates (REARCH R12 S5-serve): the view computed through
// the wasm boundary — the estate's own issuer DO supplies the
// passport, the estate's own registry DO supplies the lens, and the
// projection is the native project()'s own output shape.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";
import { RegistryDO } from "../src/registry-do";
import { view } from "../src/views";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const LENS_ITEM = {
  identifier: "urn:unidpp:profile:eu-espr-electronics",
  register: "unidpp-registry",
  item_class: "profile",
  title: "The EU battery lens",
  manifest: {
    version: "1.0.0",
    profile: {
      id: "urn:unidpp:profile:eu-espr-electronics",
      axes: { jurisdiction: "EU", sector: "batteries", characteristic: "battery-passport" },
      trigger: "Any",
      min_capability: "silent",
      freshness: "Static",
      effective: { from: "2027-01-01T00:00:00Z" },
      data_points: [
        { register: "unidpp", item: "passport-id", version: "1.0.0" },
        { register: "unidpp", item: "product-id", version: "1.0.0" },
        { register: "unidpp", item: "capability", version: "1.0.0" },
        { register: "unidpp", item: "validity-from", version: "1.0.0" },
        { register: "unidpp", item: "log-head", version: "1.0.0" },
      ],
      crypto_suites: ["ecdsa-p256"],
      confidential: false,
      resolution: "public",
      edge_visibility: "blind",
      traversal: "role-scoped",
    },
    bindings: [
      { element: "unidpp/passport-id@1.0.0", source: "passport_id", min_trust: "self-declared", min_capability: "silent" },
      { element: "unidpp/product-id@1.0.0", source: "product_id", min_trust: "self-declared", min_capability: "silent" },
      { element: "unidpp/capability@1.0.0", source: "capability", min_trust: "self-declared", min_capability: "silent" },
      { element: "unidpp/validity-from@1.0.0", source: "validity.from", min_trust: "self-declared", min_capability: "silent" },
      { element: "unidpp/log-head@1.0.0", source: "log.head", min_trust: "self-declared", min_capability: "silent" },
    ],
    presentation: {
      template_ref: "urn:unidpp:template:consumer-v1",
      formatting: { unit_position: "suffix", decimal_digits: 1, fallback_lang: "en" },
      sections: [
        {
          id: "product",
          labels: { en: "Product" },
          elements: [
            { element: "unidpp/passport-id@1.0.0", labels: { en: "Passport" } },
            { element: "unidpp/product-id@1.0.0", labels: { en: "Product" } },
          ],
        },
      ],
    },
  },
};

describe("the views surface", () => {
  it("projects a minted passport through the wasm boundary", async () => {
    const issuer = new IssuerDO(storage());
    const registry = new RegistryDO(storage());
    await registry.fetch(
      new Request("https://do.internal/items", {
        method: "POST",
        body: JSON.stringify({
          register_id: "unidpp-registry",
          item_id: "urn:unidpp:profile:eu-espr-electronics",
          class: "profile",
          definition: "The EU battery lens",
          version: "1.0.0",
          manifest: LENS_ITEM.manifest,
        }),
      }),
    );
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({ identity: "https://product.example.org/views-1" }),
      }),
    );
    expect(minted.status).toBe(201);
    const passport = (await minted.json()) as { passport_id: string };

    const response = await view(
      new Request(
        `https://unidpp.workers.dev/views/view?passport=${encodeURIComponent(passport.passport_id)}&profile=urn:unidpp:profile:eu-espr-electronics&actor=views-test`,
      ),
      {
        ISSUER: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: issuer.fetch.bind(issuer) }),
        },
        REGISTRY: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: registry.fetch.bind(registry) }),
        },
      },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      subject?: unknown;
      passport?: { source?: string };
      coverage?: unknown;
      as_of?: string;
    };
    expect(body.passport?.source).toBe("registry");
    expect(body.as_of).toBeTruthy();
  });

  it("falls back to the built-in lens and demo passport", async () => {
    const issuer = new IssuerDO(storage());
    const registry = new RegistryDO(storage());
    const response = await view(
      new Request(
        "https://unidpp.workers.dev/views/view?passport=urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345&profile=urn:unidpp:profile:eu-espr-electronics&actor=views-test",
      ),
      {
        ISSUER: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: issuer.fetch.bind(issuer) }),
        },
        REGISTRY: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: registry.fetch.bind(registry) }),
        },
      },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { passport?: { source?: string } };
    // The registry has no lens item: the fixture fallback serves it
    // and states its source.
    expect(body.passport?.source).toBe("fixtures");
  });

  it("states the misses", async () => {
    const issuer = new IssuerDO(storage());
    const registry = new RegistryDO(storage());
    const noPassport = await view(
      new Request(
        "https://unidpp.workers.dev/views/view?passport=absent&profile=x&actor=t",
      ),
      {
        ISSUER: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: issuer.fetch.bind(issuer) }),
        },
        REGISTRY: {
          idFromName: (n: string) => n,
          get: () => ({ fetch: registry.fetch.bind(registry) }),
        },
      },
    );
    expect(noPassport.status).toBe(404);
    const noProfile = await view(
      new Request("https://unidpp.workers.dev/views/view?passport=x&actor=t"),
      {},
    );
    expect(noProfile.status).toBe(400);
  });
});
