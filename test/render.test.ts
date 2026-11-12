// The render gates (REARCH R12 S5-serve): the EN 18222 document and
// the UNTP triad computed through the wasm boundary — the issuer DO
// supplies the passport (the GTIN route addresses the key), the
// built-in demo passport is the fixture fallback for the UNTP route,
// and the misses 404 no-information (I12).

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";
import { render } from "../src/render";

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

const envWith = (issuer: IssuerDO) => ({
  ISSUER: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: issuer.fetch.bind(issuer) }),
  },
});

describe("the render surface", () => {
  it("renders a GS1-keyed passport in the EN 18222 shape", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({ identity: "gtin:4006381333931" }),
      }),
    );
    expect(minted.status).toBe(201);
    const served = await render(
      "/en18222/v1/dppsByProductId/4006381333931",
      new Request(
        "https://app.unidpp.org/render/en18222/v1/dppsByProductId/4006381333931?representation=full",
      ),
      envWith(issuer),
    );
    expect(served.status).toBe(200);
    const document = (await served.json()) as {
      digitalProductPassportId?: string;
      uniqueProductIdentifier?: string;
      granularity?: string;
      dppSchemaVersion?: string;
      dppStatus?: string;
      lastUpdated?: string;
      contentSpecificationIds?: string[];
      elements?: { elementId: string; elements: { value: string }[] }[];
    };
    expect(document.uniqueProductIdentifier).toBe("4006381333931");
    expect(document.granularity).toBe("Model");
    expect(document.dppSchemaVersion).toBe("0.1");
    expect(document.dppStatus).toBe("active");
    expect(document.contentSpecificationIds).toContain("EN 18223:2026");
    expect(Array.isArray(document.elements)).toBe(true);
    // Every full-form value is a string (the artifacts' print rule).
    for (const collection of document.elements ?? []) {
      for (const leaf of collection.elements) {
        expect(typeof leaf.value).toBe("string");
      }
    }
    // The compressed form keys the collections directly with native
    // values and drops `elements`.
    const compressed = await render(
      "/en18222/v1/dppsByProductId/4006381333931",
      new Request(
        "https://app.unidpp.org/render/en18222/v1/dppsByProductId/4006381333931",
      ),
      envWith(issuer),
    );
    expect(compressed.status).toBe(200);
    const flat = (await compressed.json()) as Record<string, unknown>;
    expect(flat.elements).toBeUndefined();
    expect(flat.uniqueProductIdentifier).toBe("4006381333931");
  });

  it("renders the demo passport as the UNTP triad from the fixtures", async () => {
    const issuer = new IssuerDO(storage());
    const served = await render(
      "/untp/product/urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
      new Request(
        "https://app.unidpp.org/render/untp/product/urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
      ),
      envWith(issuer),
    );
    expect(served.status).toBe(200);
    const triad = (await served.json()) as {
      rendering?: { source?: string };
      verdict?: { outcome?: string; coverage?: { signatures?: { verified?: number } } };
      passport?: { type?: string[] };
      link?: unknown;
    };
    expect(triad.rendering?.source).toBe("fixture");
    expect(triad.verdict?.outcome).toBe("pass");
    expect(triad.passport?.type).toContain("DigitalProductPassport");

  });

  it("renders an issuer passport as the UNTP triad from the issuer", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({ identity: "cpid:urn:test:render-untp" }),
      }),
    );
    expect(minted.status).toBe(201);
    const { passport_id: passportId } = (await minted.json()) as { passport_id: string };
    const served = await render(
      `/untp/product/${encodeURIComponent(passportId)}`,
      new Request(`https://app.unidpp.org/render/untp/product/${encodeURIComponent(passportId)}`),
      envWith(issuer),
    );
    expect(served.status).toBe(200);
    const triad = (await served.json()) as { rendering?: { source?: string } };
    expect(triad.rendering?.source).toBe("issuer");
  });

  it("carries the issuer's bound profile layer into the renderings", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({
          identity: "gtin:4006381333931",
          profiles: [
            { id: "urn:unidpp:profile:eu-espr-electronics", version: "1.0.0", effective_from: "2027-01-01T00:00:00Z" },
          ],
        }),
      }),
    );
    expect(minted.status).toBe(201);
    // The bound layer reads beside the document.
    const read = (await (
      await issuer.fetch(new Request("https://do.internal/passports"))
    ).json()) as { passports: { passport_id: string }[] };
    const one = (await (
      await issuer.fetch(
        new Request(`https://do.internal/passports/${encodeURIComponent(read.passports[0].passport_id)}`),
      )
    ).json()) as { profiles?: { id: string; version: string }[] };
    expect(one.profiles).toHaveLength(1);
    expect(one.profiles?.[0].id).toBe("urn:unidpp:profile:eu-espr-electronics");
    // The EN render's contentSpecificationIds carry the bound refs.
    const en = await render(
      "/en18222/v1/dppsByProductId/4006381333931",
      new Request(
        "https://app.unidpp.org/render/en18222/v1/dppsByProductId/4006381333931?representation=full",
      ),
      envWith(issuer),
    );
    expect(en.status).toBe(200);
    const document = (await en.json()) as { contentSpecificationIds?: string[] };
    expect(document.contentSpecificationIds).toContain(
      "urn:unidpp:profile:eu-espr-electronics@1.0.0",
    );
    // The UNTP triad's standardsConformance carries the bound refs.
    const minted2 = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({
          identity: "cpid:urn:test:bound-profiles",
          profiles: [{ id: "urn:unidpp:profile:eu-espr-electronics", version: "1.0.0" }],
        }),
      }),
    );
    const { passport_id: boundId } = (await minted2.json()) as { passport_id: string };
    const triad = await render(
      `/untp/product/${encodeURIComponent(boundId)}`,
      new Request(`https://app.unidpp.org/render/untp/product/${encodeURIComponent(boundId)}`),
      envWith(issuer),
    );
    expect(triad.status).toBe(200);
    const body = (await triad.json()) as {
      passport?: { standardsConformance?: { standard?: string; conformanceVersion?: string }[] };
    };
    expect(body.passport?.standardsConformance?.[0]?.standard).toBe(
      "urn:unidpp:profile:eu-espr-electronics",
    );
    expect(body.passport?.standardsConformance?.[0]?.conformanceVersion).toBe("1.0.0");
  });

  it("refuses a bound profile without id or version", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await issuer.fetch(
      new Request("https://do.internal/passports", {
        method: "POST",
        body: JSON.stringify({
          identity: "cpid:urn:test:bad-binding",
          profiles: [{ id: "urn:unidpp:profile:x" }],
        }),
      }),
    );
    expect(minted.status).toBe(400);
    const body = (await minted.json()) as { error: string };
    expect(body.error).toContain("`id` and `version`");
  });

  it("states the misses and the refusals", async () => {
    const issuer = new IssuerDO(storage());
    const noGtin = await render(
      "/en18222/v1/dppsByProductId/0000000000000",
      new Request("https://app.unidpp.org/render/en18222/v1/dppsByProductId/0000000000000"),
      envWith(issuer),
    );
    expect(noGtin.status).toBe(404);
    const noPassport = await render(
      "/untp/product/absent",
      new Request("https://app.unidpp.org/render/untp/product/absent"),
      envWith(issuer),
    );
    expect(noPassport.status).toBe(404);
    const badRepresentation = await render(
      "/en18222/v1/dppsByProductId/4006381333931",
      new Request(
        "https://app.unidpp.org/render/en18222/v1/dppsByProductId/4006381333931?representation=wide",
      ),
      envWith(issuer),
    );
    expect(badRepresentation.status).toBe(400);
    const badFreshness = await render(
      "/untp/product/urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
      new Request(
        "https://app.unidpp.org/render/untp/product/urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345?freshness=soon",
      ),
      envWith(issuer),
    );
    expect(badFreshness.status).toBe(400);
  });
});
