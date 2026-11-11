// The trust surface on a Durable Object (REARCH R12 S3): the
// operator keyring derived deterministically from the seed through
// the wasm boundary, and the receipt-verification path — a third
// party holding only the served anchors verifies a log receipt's
// signed tree head with no connection to the log.

import { journalFor, Journal } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";

interface Anchor {
  key_id: string;
  suite: string;
  public: string;
}

const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

function operatorSeed(core: CoreExports, envSeed: string | undefined): Uint8Array {
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return unhex(envSeed.trim());
  }
  // The deterministic dev seed: the digest of the fixed label, the
  // same degrade the native keyring carries.
  const label = "UNIDPP-LOG/OPERATOR-SEED";
  const bytes = new TextEncoder().encode(label);
  const ptr = core.unidpp_alloc(bytes.length);
  new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, bytes.length, outPtr);
  const seed = out.slice();
  core.unidpp_free(ptr, bytes.length);
  core.unidpp_free(outPtr, 32);
  return seed;
}

function anchorOf(core: CoreExports, seed: Uint8Array): Anchor {
  const seedPtr = core.unidpp_alloc(32);
  new Uint8Array(core.memory.buffer, seedPtr, 32).set(seed);
  const publicPtr = core.unidpp_alloc(32);
  const rc = core.unidpp_head_public(seedPtr, publicPtr);
  const publicKey = hex(new Uint8Array(core.memory.buffer, publicPtr, 32).slice());
  const idLen = core.unidpp_head_key_id(seedPtr, publicPtr);
  const keyId = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, publicPtr, idLen).slice(),
  );
  core.unidpp_free(seedPtr, 32);
  core.unidpp_free(publicPtr, 32);
  if (rc !== 0) throw new Error("the operator key derivation failed");
  return { key_id: keyId, suite: "ed25519", public: publicKey };
}

export class TrustDO {
  private journal: Journal;
  private core: CoreExports;
  private anchor: Anchor | null = null;

  constructor(
    stateOrStorage: unknown,
    private readonly env: Record<string, string | undefined>,
  ) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
  }

  private anchorOf(): Anchor {
    if (!this.anchor) {
      this.anchor = anchorOf(this.core, operatorSeed(this.core, this.env.UNIDPP_LOG_SEED));
    }
    return this.anchor;
  }

  async fetch(request: Request): Promise<Response> {
    await this.journal.all();
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (path === "/keyring" && request.method === "GET") {
      const anchor = this.anchorOf();
      return new Response(
        JSON.stringify({
          keyring: "unidpp-trust",
          anchors: [anchor],
          as_of: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        }),
        { headers: { "content-type": "application/json", "x-as-of": new Date().toISOString() } },
      );
    }
    if (path === "/verify" && request.method === "POST") {
      return this.verify(request);
    }
    return new Response(JSON.stringify({ error: "no such path" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }

  // Verify a signed tree head against the served anchor: the third
  // party's F1 path, byte-for-byte the native verification's inputs
  // (the canonical bytes are built inside the wasm boundary).
  private async verify(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return new Response(JSON.stringify({ error: "invalid JSON body" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const treeHead = v.tree_head as
      | {
          log_id: string;
          tree_size: number;
          timestamp: string;
          root: string;
          signature: { signature: string };
        }
      | undefined;
    if (!treeHead?.log_id || !treeHead.tree_size || !treeHead.root || !treeHead.signature) {
      return new Response(JSON.stringify({ error: "`tree_head` is required" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const ms = Date.parse(treeHead.timestamp);
    const secs = Math.floor(ms / 1000);
    const nanos = (ms % 1000) * 1_000_000;
    const core = this.core;
    const anchor = this.anchorOf();
    const publicPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, publicPtr, 32).set(unhex(anchor.public));
    const logBytes = new TextEncoder().encode(treeHead.log_id);
    const logPtr = core.unidpp_alloc(logBytes.length);
    new Uint8Array(core.memory.buffer, logPtr, logBytes.length).set(logBytes);
    const rootPtr = core.unidpp_alloc(32);
    new Uint8Array(core.memory.buffer, rootPtr, 32).set(unhex(treeHead.root));
    const sigPtr = core.unidpp_alloc(64);
    new Uint8Array(core.memory.buffer, sigPtr, 64).set(unhex(treeHead.signature.signature));
    const rc = core.unidpp_sth_verify(
      publicPtr,
      logPtr,
      logBytes.length,
      BigInt(treeHead.tree_size),
      BigInt(secs),
      nanos,
      rootPtr,
      sigPtr,
    );
    [publicPtr, logPtr, rootPtr, sigPtr].forEach((ptr, i) =>
      core.unidpp_free(ptr, [32, logBytes.length, 32, 64][i]),
    );
    return new Response(
      JSON.stringify({
        verified: rc === 1,
        anchor: { key_id: anchor.key_id, suite: anchor.suite },
        log_id: treeHead.log_id,
        tree_size: treeHead.tree_size,
      }),
      { headers: { "content-type": "application/json", "x-as-of": new Date().toISOString() } },
    );
  }
}
