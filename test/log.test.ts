// S3's gates (REARCH R12): the TS tree's roots match the wasm
// core's digests at every size (the cross-check the native tree.rs
// itself runs), receipts derive inclusion proofs, the signed tree
// head verifies under the served anchor — and a tampered head
// refuses.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { MerkleTree } from "../src/tree";
import { LogDO } from "../src/log-do";
import { TrustDO } from "../src/trust-do";
import { useWorkerCore } from "../src/mount";

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

const commitment = (i: number): string => {
  const data = new TextEncoder().encode(`unidpp-log/s3-entry:${i}`);
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  let hex = "";
  for (const byte of out) hex += byte.toString(16).padStart(2, "0");
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return hex;
};

describe("the TS tree against the wasm digests", () => {
  it("roots match at every size to 33", () => {
    for (let n = 0; n <= 33; n += 1) {
      const tree = new MerkleTree((data) => {
        const ptr = core.unidpp_alloc(data.length);
        new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
        const outPtr = core.unidpp_alloc(32);
        const out = new Uint8Array(core.memory.buffer, outPtr, 32);
        core.unidpp_sha256(ptr, data.length, outPtr);
        const digest = out.slice();
        core.unidpp_free(ptr, data.length);
        core.unidpp_free(outPtr, 32);
        return digest;
      });
      const expectedRoots: (string | null)[] = [];
      // The reference: hash the leaves the way the tree does and take
      // the root each time (the wasm core is the reference).
      const leaves: Uint8Array[] = [];
      for (let i = 0; i < n; i += 1) {
        const entry = unhex(commitment(i));
        const data = new Uint8Array(33);
        data[0] = 0x01;
        data.set(entry, 1);
        const ptr = core.unidpp_alloc(data.length);
        new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
        const outPtr = core.unidpp_alloc(32);
        const out = new Uint8Array(core.memory.buffer, outPtr, 32);
        core.unidpp_sha256(ptr, data.length, outPtr);
        leaves.push(out.slice());
        core.unidpp_free(ptr, data.length);
        core.unidpp_free(outPtr, 32);
        tree.append(entry);
        expectedRoots.push(tree.root() ? toHex(tree.root()!) : null);
      }
      // Re-derive the roots independently by folding peaks per size.
      for (let size = 1; size <= n; size += 1) {
        const fold = (hashes: Uint8Array[]): Uint8Array => {
          if (hashes.length === 1) return hashes[0];
          // Fold per the RFC 6962 MTH recursion the tree implements.
          const k = 1 << Math.floor(Math.log2(hashes.length - 1));
          const left = hashes.slice(0, k);
          const right = hashes.slice(k);
          if (right.length === 0) return fold(left);
          const data = new Uint8Array(65);
          data[0] = 0x02;
          data.set(fold(left), 1);
          data.set(fold(right), 33);
          const ptr = core.unidpp_alloc(data.length);
          new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
          const outPtr = core.unidpp_alloc(32);
          const out = new Uint8Array(core.memory.buffer, outPtr, 32);
          core.unidpp_sha256(ptr, data.length, outPtr);
          const digest = out.slice();
          core.unidpp_free(ptr, data.length);
          core.unidpp_free(outPtr, 32);
          return digest;
        };
        const root = fold(leaves.slice(0, size));
        expect(toHex(root)).toBe(expectedRoots[size - 1]);
      }
    }
  });
});

const toHex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};
const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

describe("the log Durable Object", () => {
  it("appends, receipts, and the head verifies under the anchor", async () => {
    const log = new LogDO(storage(), {});
    const commitments = [1, 2, 3, 4, 5].map((i) => commitment(i));
    let receipt: Record<string, unknown> | null = null;
    for (const commitment of commitments) {
      const response = await log.fetch(
        new Request("https://do.internal/commitments", {
          method: "POST",
          body: JSON.stringify({ subject: `s3:${commitment.slice(0, 12)}`, commitment }),
        }),
      );
      expect(response.status).toBe(201);
      receipt = (await response.json()) as Record<string, unknown>;
    }
    expect(receipt).toBeTruthy();
    const cast = receipt as {
      seq: number;
      log_id: string;
      inclusion: { tree_size: number; path: unknown[] };
      tree_head: { log_id: string; tree_size: number; root: string; signature: { signature: string; suite: string } };
      logged_at: string;
    };
    expect(cast.seq).toBe(5);
    expect(cast.inclusion.tree_size).toBe(5);
    expect(cast.inclusion.path.length).toBeGreaterThan(0);
    expect(cast.tree_head.signature.suite).toBe("ed25519");

    // The head answers and the trust surface verifies the receipt's
    // tree head against the served anchor.
    const trust = new TrustDO(storage(), {});
    const keyring = (await (
      await trust.fetch(new Request("https://do.internal/keyring"))
    ).json()) as { anchors: { key_id: string; public: string; suite: string }[] };
    expect(keyring.anchors.length).toBe(1);
    expect(keyring.anchors[0].suite).toBe("ed25519");
    const verdict = (await (
      await trust.fetch(
        new Request("https://do.internal/verify", {
          method: "POST",
          body: JSON.stringify({ tree_head: cast.tree_head }),
        }),
      )
    ).json()) as { verified: boolean };
    expect(verdict.verified).toBe(true);

    // A tampered root refuses.
    const tampered = {
      ...cast.tree_head,
      root: cast.tree_head.root.slice(0, -2) + "00",
    };
    const refusal = (await (
      await trust.fetch(
        new Request("https://do.internal/verify", {
          method: "POST",
          body: JSON.stringify({ tree_head: tampered }),
        }),
      )
    ).json()) as { verified: boolean };
    expect(refusal.verified).toBe(false);
  });

  it("replays the journal and the receipts survive", async () => {
    const map = new Map<string, unknown>();
    const store = {
      put: async (k: string, v: unknown) => void map.set(k, v),
      get: async (k: string) => map.get(k),
      list: async ({ prefix }: { prefix: string }) =>
        new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
    };
    const first = new LogDO(store, {});
    const response = await first.fetch(
      new Request("https://do.internal/commitments", {
        method: "POST",
        body: JSON.stringify({ subject: "s3:replay", commitment: commitment(9) }),
      }),
    );
    expect(response.status).toBe(201);
    // A fresh instance over the same storage replays the journal.
    const second = new LogDO(store, {});
    const head = await second.fetch(new Request("https://do.internal/tree/head"));
    expect(head.status).toBe(200);
    const sth = (await head.json()) as { tree_size: number };
    expect(sth.tree_size).toBe(1);
    const read = await second.fetch(new Request("https://do.internal/receipt/1"));
    expect(read.status).toBe(200);
  });

  it("guards appends when the deployment sets a token", async () => {
    const log = new LogDO(storage(), { UNIDPP_LOG_APPEND_TOKEN: "sekrit" });
    const refused = await log.fetch(
      new Request("https://do.internal/commitments", {
        method: "POST",
        body: JSON.stringify({ subject: "s", commitment: commitment(1) }),
      }),
    );
    expect(refused.status).toBe(401);
    const allowed = await log.fetch(
      new Request("https://do.internal/commitments", {
        method: "POST",
        headers: { authorization: "Bearer sekrit" },
        body: JSON.stringify({ subject: "s", commitment: commitment(1) }),
      }),
    );
    expect(allowed.status).toBe(201);
  });
});

describe("the corpus through the log's commitments", () => {
  beforeAll(() => {
    void 0;
  });
  it("accepts a canonical vector digest as a commitment", async () => {
    const vector = JSON.parse(
      readFileSync(
        path.join(HERE, "..", "..", "unidpp-py", "tests", "harness", "canonical", "frozen-view.json"),
        "utf8",
      ),
    );
    const log = new LogDO(storage(), {});
    const response = await log.fetch(
      new Request("https://do.internal/commitments", {
        method: "POST",
        body: JSON.stringify({
          subject: "urn:unidpp:log:s3-vector",
          commitment: vector.digest_hex,
        }),
      }),
    );
    expect(response.status).toBe(201);
  });
});
