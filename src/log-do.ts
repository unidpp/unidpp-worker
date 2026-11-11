// The transparency log on a Durable Object (REARCH R12 S3): append
// only commitments, inclusion receipts derived from the TS tree over
// the wasm hashes, and the signed tree head signed by the wasm
// boundary (the signatif canonical bytes, the operator key derived
// from the seed, the secret never leaving the module). The append
// guard rides the UNIDPP_LOG_APPEND_TOKEN var when the deployment
// sets one; an unconfigured deployment serves open, exactly as the
// native module does.

import { JournalOp, journalFor, Journal } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";
import { MerkleTree, ProofNode } from "./tree";

export interface CommitRecord {
  seq: number;
  logged_at: string;
  subject: string;
  commitment: string;
  salt_ref: number | null;
}

const hexOk = (value: string): boolean =>
  /^[0-9a-fA-F]{64}$/.test(value);

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const json = (status: number, body: unknown, asOf?: string): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...(asOf ? { "x-as-of": asOf } : {}),
    },
  });

const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));

// The operator seed: UNIDPP_LOG_SEED when set; otherwise the
// deterministic dev seed (sha256 over a fixed label) — the same
// degrade the native keyring carries, derived here through the wasm
// core.
function operatorSeed(core: CoreExports, envSeed: string | undefined): Uint8Array {
  if (envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim())) {
    return unhex(envSeed.trim());
  }
  return unhex(coreDigestOf(core, "UNIDPP-LOG/OPERATOR-SEED"));
}

function coreDigestOf(core: CoreExports, text: string): string {
  const ptr = core.unidpp_alloc(text.length);
  new Uint8Array(core.memory.buffer, ptr, text.length).set(
    new TextEncoder().encode(text),
  );
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, text.length, outPtr);
  const value = hex(out);
  core.unidpp_free(ptr, text.length);
  core.unidpp_free(outPtr, 32);
  return value;
}

function utf8Bytes(core: CoreExports, text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export class LogDO {
  private records: CommitRecord[] = [];
  private tree: MerkleTree | null = null;
  private loaded = false;
  private journal: Journal;
  private core: CoreExports;

  constructor(
    stateOrStorage: unknown,
    private readonly env: Record<string, string | undefined>,
  ) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
  }

  private loadTree(): MerkleTree {
    if (!this.tree) {
      this.tree = new MerkleTree((data) => {
        const ptr = this.core.unidpp_alloc(data.length);
        new Uint8Array(this.core.memory.buffer, ptr, data.length).set(data);
        const outPtr = this.core.unidpp_alloc(32);
        const out = new Uint8Array(this.core.memory.buffer, outPtr, 32);
        this.core.unidpp_sha256(ptr, data.length, outPtr);
        const digest = out.slice();
        this.core.unidpp_free(ptr, data.length);
        this.core.unidpp_free(outPtr, 32);
        return digest;
      });
    }
    return this.tree;
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      for (const op of await this.journal.all()) {
        this.apply(op);
      }
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") return json(200, { status: "ok" });
    if (path === "/commitments" && request.method === "POST") {
      return this.commit(request);
    }
    const receipt = path.match(/^\/receipt\/(\d+)$/);
    if (receipt && request.method === "GET") {
      return this.receipt(Number(receipt[1]), url);
    }
    if (path === "/tree/head" && request.method === "GET") return this.head();
    if (path === "/tree/consistency" && request.method === "GET") {
      return this.consistency(url);
    }
    return json(404, { error: "no such path" });
  }

  private apply(op: JournalOp): void {
    if (op.op === "commit") {
      const record = op.record as CommitRecord;
      this.records.push(record);
      this.loadTree().append(unhex(record.commitment));
    }
  }

  private async commit(request: Request): Promise<Response> {
    const guard = this.guardFor(request);
    if (guard) return guard;
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const subject = (v.subject as string)?.trim();
    if (!subject) return badRequest("`subject` is required");
    if (subject.length > 512) {
      return badRequest("`subject` must be at most 512 characters");
    }
    const commitment = (v.commitment as string)?.trim();
    if (!commitment || !hexOk(commitment)) {
      return badRequest("`commitment` must be 64-char hex");
    }
    const saltRef =
      typeof v.salt_ref === "number" ? (v.salt_ref as number) : null;
    const loggedAt = isoNow();
    const seq = this.records.length + 1;
    const record: CommitRecord = {
      seq,
      logged_at: loggedAt,
      subject,
      commitment,
      salt_ref: saltRef,
    };
    await this.journal.append({ op: "commit", record });
    this.apply({ op: "commit", record });
    return json(201, await this.receiptJson(record), loggedAt);
  }

  private isoOf(iso: string): { secs: number; nanos: number } {
    const ms = Date.parse(iso);
    const secs = Math.floor(ms / 1000);
    const nanos = (ms % 1000) * 1_000_000;
    return { secs, nanos };
  }

  private sthOf(asOfMs: number): {
    log_id: string;
    tree_size: number;
    timestamp: string;
    root: string;
    signature: { suite: string; key_id: string; signature: string };
  } {
    const tree = this.loadTree();
    const root = tree.root();
    if (!root) throw new Error("the tree is empty");
    const logId = this.env.UNIDPP_LOG_ID ?? "unidpp-log";
    const timestamp = new Date(asOfMs).toISOString().replace(/\.\d{3}Z$/, "Z");
    const { secs, nanos } = this.isoOf(timestamp);
    const seed = operatorSeed(this.core, this.env.UNIDPP_LOG_SEED);
    const seedPtr = this.core.unidpp_alloc(32);
    new Uint8Array(this.core.memory.buffer, seedPtr, 32).set(seed);
    const logBytes = utf8Bytes(this.core, logId);
    const logPtr = this.core.unidpp_alloc(logBytes.length);
    new Uint8Array(this.core.memory.buffer, logPtr, logBytes.length).set(logBytes);
    const rootPtr = this.core.unidpp_alloc(32);
    new Uint8Array(this.core.memory.buffer, rootPtr, 32).set(root);
    const sigPtr = this.core.unidpp_alloc(64);
    const rc = this.core.unidpp_sth_sign(
      seedPtr,
      logPtr,
      logBytes.length,
      BigInt(tree.size),
      BigInt(secs),
      nanos,
      rootPtr,
      sigPtr,
    );
    const signature = hex(new Uint8Array(this.core.memory.buffer, sigPtr, 64).slice());
    const keyIdLen = this.core.unidpp_head_key_id(seedPtr, sigPtr);
    const keyId = new TextDecoder().decode(
      new Uint8Array(this.core.memory.buffer, sigPtr, keyIdLen).slice(),
    );
    [seedPtr, logPtr, rootPtr, sigPtr].forEach((ptr, i) =>
      this.core.unidpp_free(ptr, [32, logBytes.length, 32, 64][i]),
    );
    if (rc !== 0) throw new Error(`the tree head signature failed (${rc})`);
    return {
      log_id: logId,
      tree_size: tree.size,
      timestamp,
      root: hex(root),
      signature: { suite: "ed25519", key_id: keyId, signature },
    };
  }

  private async receiptJson(record: CommitRecord): Promise<Record<string, unknown>> {
    const tree = this.loadTree();
    const index = record.seq - 1;
    const path = tree.inclusionPath(index, tree.size);
    const leaf = hex(unhex(leafHashOf(this.core, record.commitment)));
    const { secs, nanos } = this.isoOf(record.logged_at);
    void secs;
    void nanos;
    const sth = this.sthOf(Date.parse(record.logged_at));
    return {
      receipt_id: String(record.seq),
      log_id: sth.log_id,
      seq: record.seq,
      subject: record.subject,
      commitment: record.commitment,
      salt_ref: record.salt_ref,
      logged_at: record.logged_at,
      inclusion: {
        leaf_index: index,
        tree_size: tree.size,
        leaf_hash: leaf,
        commitment: record.commitment,
        path: path.map((node: ProofNode) => ({
          sibling: hex(node.sibling),
          side: node.side,
        })),
      },
      tree_head: sth,
      operator: { key_id: sth.signature.key_id, suite: "ed25519" },
    };
  }

  private async receipt(seq: number, url: URL): Promise<Response> {
    void url;
    const record = this.records.find((r) => r.seq === seq);
    if (!record) return json(404, { error: `no receipt for seq ${seq}` });
    return json(200, await this.receiptJson(record), isoNow());
  }

  private head(): Response {
    const tree = this.loadTree();
    if (tree.size === 0) return json(200, { status: "no entries" });
    return json(200, this.sthOf(Date.now()), isoNow());
  }

  private consistency(url: URL): Response {
    const from = url.searchParams.get("from");
    if (!from) return badRequest("`from` is required");
    const oldSize = Number(from);
    if (!Number.isInteger(oldSize) || oldSize < 0) {
      return badRequest("`from` must be a non-negative integer");
    }
    const tree = this.loadTree();
    if (oldSize > tree.size) return json(404, { error: "the prefix is larger than the tree" });
    const path = tree
      .consistencyPath(oldSize)
      .map((h) => hex(h));
    return json(200, { from: oldSize, to: tree.size, path }, isoNow());
  }

  private guardFor(request: Request): Response | null {
    const token = this.env.UNIDPP_LOG_APPEND_TOKEN;
    if (!token) return null;
    const presented = request.headers.get("authorization");
    if (presented !== `Bearer ${token}`) {
      return json(401, { error: "the log append guard refuses" });
    }
    return null;
  }
}

function leafHashOf(core: CoreExports, commitmentHex: string): string {
  const entry = unhex(commitmentHex);
  const data = new Uint8Array(33);
  data[0] = 0x01;
  data.set(entry, 1);
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  const value = hex(out);
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return value;
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

