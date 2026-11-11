// The byte-identity gate (REARCH R12): the golden documents the
// Worker embeds are exactly the committed repo goldens, the union
// document is served verbatim, every module prefix answers, and the
// discovery document carries every module's entries.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { MODULES, VERSION, discoveryDocument, handle, coreDigest, useCore } from "../src/estate";
import { CoreExports } from "../src/wasm";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDENS = path.join(HERE, "..", "goldens");

const golden = (name: string) => readFileSync(path.join(GOLDENS, name), "utf8");

// The same pure module the worker mounts, instantiated from bytes.
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
useCore(instance.exports as unknown as CoreExports);

const serve = async (path: string): Promise<Response> =>
  handle(new Request(`https://unidpp.workers.dev${path}`));

describe("the union surface", () => {
  it("serves the union document byte-identically", async () => {
    const response = await serve("/openapi.yaml");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(golden("union-golden.yaml"));
  });

  it("answers the deployment's own surface", async () => {
    expect((await serve("/healthz")).status).toBe(200);
    const version = (await (await serve("/version")).json()) as Record<string, string>;
    expect(version.service).toBe("unidpp");
    expect(version.runtime).toBe("cloudflare-workers");
    expect(version.version).toBe(VERSION);
    const discovery = (await (await serve("/")).json()) as {
      service: string;
      modules: { name: string; contract: string }[];
    };
    expect(discovery.service).toBe("unidpp");
    expect(discovery.modules).toHaveLength(MODULES.length);
    for (const [index, [name]] of MODULES.entries()) {
      expect(discovery.modules[index].name).toBe(name);
      expect(discovery.modules[index].contract).toBe(`/${name}/openapi.yaml`);
    }
    expect(discoveryDocument().service).toBe("unidpp");
  });

  for (const [name, source, golden_text] of MODULES) {
    it(`serves ${name} byte-identically (${source})`, async () => {
      expect(golden_text.length).toBeGreaterThan(0);
      const yaml = await serve(`/${name}/openapi.yaml`);
      expect(yaml.status).toBe(200);
      expect(await yaml.text()).toBe(golden_text);
      expect((await serve(`/${name}/healthz`)).status).toBe(200);
    });
  }

  it("refuses unknown paths with the stated 404", async () => {
    const response = await serve("/nope");
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "no such path" });
  });

  it("digests through the wasm core like the model crate", () => {
    expect(coreDigest(new TextEncoder().encode(""))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
