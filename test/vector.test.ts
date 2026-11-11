// The vector corpus replay against the wasm core (REARCH R12): the
// canonical encoding is pinned by the corpus as bytes and digest; the
// Worker's digest path is the model crate's own sha256, compiled to
// wasm — the bytes must agree, exactly.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { readFileSync as readFile } from "node:fs";
import { CoreExports, digestHex } from "../src/wasm";


const HERE = path.dirname(fileURLToPath(import.meta.url));
const CANONICAL = path.join(HERE, "..", "..", "unidpp-py", "tests", "harness", "canonical");

// The canonical vectors: pinned bytes and digest, the shape the
// digest path replays. (The other corpus files pin structure, not
// canonical bytes; the digest replay rides the ones that do.)
const corpusFiles = [
  "frozen-view.json",
  "attestation-statement.json",
  "interop-declaration.json",
];

describe("the vector corpus through the wasm core", () => {
  const core: CoreExports = (() => {
    const bytes = readFile(path.join(HERE, "..", "src", "core_bg.wasm"));
    const module = new WebAssembly.Module(bytes);
    // The module carries no imports: a bare instantiation is the
    // whole contract.
    return new WebAssembly.Instance(module, {}).exports as unknown as CoreExports;
  })();

  const sha256_hex = (data: Uint8Array) => digestHex(core, data);

  for (const file of corpusFiles) {
    it(`replays ${file}`, () => {
      const vector = JSON.parse(
        readFileSync(path.join(CANONICAL, file), "utf8"),
      );
      const bytes = new Uint8Array(
        (vector.canonical_hex as string)
          .match(/../g)!
          .map((pair) => parseInt(pair, 16)),
      );
      expect(sha256_hex(bytes)).toBe(vector.digest_hex);
    });
  }

  it("digests the empty input like the model crate does", () => {
    expect(sha256_hex(new Uint8Array([]))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
