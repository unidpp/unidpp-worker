// The resolution gates (the audit's gap 1): the identifier forms the
// native resolver accepts resolve against the estate's register into
// RFC 9264 linksets naming the estate's own surfaces; the GS1
// conventions path form redirects; the unknown and the dark answer
// identically (I12); a bad check digit refuses.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));
import { parseIdentifier, resolvePath, resolveQuery } from "../src/resolver";

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const issuerEnv = (issuer: IssuerDO) => ({
  ISSUER: {
    idFromName: (n: string) => n,
    get: () => ({ fetch: issuer.fetch.bind(issuer) }),
  },
});

const mint = async (issuer: IssuerDO, identity: string): Promise<string> => {
  const minted = await issuer.fetch(
    new Request("https://do.internal/passports", {
      method: "POST",
      body: JSON.stringify({ identity }),
    }),
  );
  expect(minted.status).toBe(201);
  const body = (await minted.json()) as { passport_id: string };
  return body.passport_id;
};

describe("the identifier parser", () => {
  it("accepts the forms the native resolver accepts", () => {
    expect(parseIdentifier("01+08712345000011")).toEqual({
      scheme: "gtin",
      key: "08712345000011",
    });
    expect(parseIdentifier("https://id.example.org/01/08712345000011/21/X", ["01", "08712345000011", "21", "X"])).toEqual({
      scheme: "gtin",
      key: "08712345000011",
      serial: "X",
    });
    expect(parseIdentifier("cpid:urn:x:1")).toEqual({ scheme: "cpid", key: "urn:x:1" });
    expect(parseIdentifier("urn:unidpp:passport:abc")).toEqual({
      scheme: "passport",
      key: "urn:unidpp:passport:abc",
    });
  });

  it("refuses a bad check digit and an unknown scheme", () => {
    expect(parseIdentifier("01+08712345000099")).toBeNull();
    expect(parseIdentifier("acme:demo-1")).toBeNull();
    expect(parseIdentifier("12345678901234")).toBeNull();
  });
});

describe("the resolution surface", () => {
  it("resolves an element string into the linkset", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mint(issuer, "gtin:08712345000011");
    const served = await resolveQuery(
      new Request("https://app.unidpp.org/resolver/resolve?identifier=01%2B08712345000011"),
      issuerEnv(issuer),
    );
    expect(served.status).toBe(200);
    const linkset = (await served.json()) as {
      linkset: { anchor: string; link: { href: string; rel: string }[] }[];
    };
    expect(linkset.linkset[0].anchor).toBe(`urn:unidpp:passport:${passportId}`);
    const rels = linkset.linkset[0].link.map((l) => l.rel);
    expect(rels).toContain("dpp");
    expect(rels).toContain("dpp-rendering");
  });

  it("resolves the GS1 Digital Link carrier form", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mint(issuer, "gtin:08712345000011");
    const served = await resolveQuery(
      new Request(
        "https://app.unidpp.org/resolver/resolve?carrier=" +
          encodeURIComponent("https://id.example.org/01/08712345000011/21/SER123"),
      ),
      issuerEnv(issuer),
    );
    expect(served.status).toBe(200);
    if (served.status !== 200) console.log("DL-DEBUG:", await served.text());
    const linkset = (await served.json()) as { linkset: { anchor: string }[] };
    expect(linkset.linkset[0].anchor).toBe(`urn:unidpp:passport:${passportId}`);
  });

  it("redirects the GS1 path form to the default link", async () => {
    const issuer = new IssuerDO(storage());
    await mint(issuer, "gtin:08712345000011");
    const served = await resolvePath(["01", "08712345000011"], new Request("https://app.unidpp.org/resolver/01/08712345000011"), issuerEnv(issuer));
    expect(served.status).toBe(303);
    expect(served.headers.get("location")).toContain("/views/view?passport=");
    const linkset = await resolvePath(["01", "08712345000011", "linkset"], new Request("https://app.unidpp.org/resolver/01/08712345000011/linkset"), issuerEnv(issuer));
    expect(linkset.status).toBe(200);
    expect(linkset.headers.get("content-type")).toContain("application/linkset+json");
  });

  it("resolves the passport-URN form by id", async () => {
    const issuer = new IssuerDO(storage());
    const passportId = await mint(issuer, "cpid:urn:test:resolver-urn");
    const served = await resolveQuery(
      new Request(`https://app.unidpp.org/resolver/resolve?identifier=${encodeURIComponent(passportId)}`),
      issuerEnv(issuer),
    );
    expect(served.status).toBe(200);
  });

  it("answers unknown and dark identically (I12)", async () => {
    const issuer = new IssuerDO(storage());
    await mint(issuer, "gtin:08712345000011");
    const unknown = await resolveQuery(
      new Request("https://app.unidpp.org/resolver/resolve?identifier=01%2B09999999999994"),
      issuerEnv(issuer),
    );
    const dark = await resolveQuery(
      new Request("https://app.unidpp.org/resolver/resolve?identifier=cpid%3Aurn%3Adark"),
      issuerEnv(issuer),
    );
    expect(unknown.status).toBe(404);
    expect(dark.status).toBe(404);
    expect(await unknown.text()).toBe(await dark.text());
  });

  it("refuses mutually exclusive params and a bad check digit", async () => {
    const issuer = new IssuerDO(storage());
    const both = await resolveQuery(
      new Request("https://app.unidpp.org/resolver/resolve?identifier=x&carrier=y"),
      issuerEnv(issuer),
    );
    expect(both.status).toBe(400);
    const bad = await resolveQuery(
      new Request("https://app.unidpp.org/resolver/resolve?identifier=01%2B08712345000099"),
      issuerEnv(issuer),
    );
    expect(bad.status).toBe(400);
  });
});
