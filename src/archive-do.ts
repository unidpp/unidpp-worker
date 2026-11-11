// The archive on a Durable Object with R2 storage (REARCH R12 S4):
// snapshot notarization — the statement sealed by the notary key
// through the wasm boundary (the signatif slot, the TreeHead domain
// the native seal uses) — and the AIP documents in an R2 bucket. The
// anchoring hop rides the estate's own LOG Durable Object, the R7
// in-process bridge: no socket anywhere.

import { journalFor, Journal } from "./journal";
import { workerCore } from "./mount";

export interface Bucket {
  put(key: string, value: string): Promise<unknown>;
  get(key: string): Promise<{ text(): Promise<string> } | null>;
}

const sha256Hex = (core: ReturnType<typeof workerCore>, data: Uint8Array): string => {
  const ptr = core.unidpp_alloc(data.length);
  new Uint8Array(core.memory.buffer, ptr, data.length).set(data);
  const outPtr = core.unidpp_alloc(32);
  const out = new Uint8Array(core.memory.buffer, outPtr, 32);
  core.unidpp_sha256(ptr, data.length, outPtr);
  let value = "";
  for (const byte of out) value += byte.toString(16).padStart(2, "0");
  core.unidpp_free(ptr, data.length);
  core.unidpp_free(outPtr, 32);
  return value;
};

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const stamped = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-as-of": new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    },
  });

export interface SnapshotRecord {
  seq: number;
  snapshot_id: string;
  passport_id: string;
  state_hash: string;
  log_head: string;
  submitter: string | null;
  notarized_at: string;
  commitment: string;
  signature: { key_id: string; suite: string; signature: string };
  anchoring: { status: string; receipt?: unknown };
}

interface LogNamespace {
  fetch(request: Request): Promise<Response>;
}

export class ArchiveDO {
  private journal: Journal;
  private core: ReturnType<typeof workerCore>;
  private index: SnapshotRecord[] = [];
  private loaded = false;
  private bucket: Bucket | null;

  constructor(
    stateOrStorage: unknown,
    private readonly env: { ARCHIVE_BUCKET?: Bucket; LOG?: LogNamespace; UNIDPP_ARCHIVE_SIGN_SEED?: string },
  ) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
    this.bucket = this.env.ARCHIVE_BUCKET ?? null;
  }

  private seed(): Uint8Array {
    const seedText = this.env.UNIDPP_ARCHIVE_SIGN_SEED;
    if (seedText && /^[0-9a-fA-F]{64}$/.test(seedText.trim())) {
      return unhex(seedText.trim());
    }
    return unhex(sha256Hex(this.core, new TextEncoder().encode("UNIDPP-ARCHIVE/NOTARY-SEED")));
  }

  private keyId(seed: Uint8Array): string {
    const seedPtr = this.core.unidpp_alloc(32);
    new Uint8Array(this.core.memory.buffer, seedPtr, 32).set(seed);
    const idPtr = this.core.unidpp_alloc(64);
    const len = this.core.unidpp_head_key_id(seedPtr, idPtr);
    const id = new TextDecoder().decode(
      new Uint8Array(this.core.memory.buffer, idPtr, len).slice(),
    );
    this.core.unidpp_free(seedPtr, 32);
    this.core.unidpp_free(idPtr, 64);
    return id;
  }

  private seal(seed: Uint8Array, payload: Uint8Array): { key_id: string; suite: string; signature: string } {
    const seedPtr = this.core.unidpp_alloc(32);
    new Uint8Array(this.core.memory.buffer, seedPtr, 32).set(seed);
    const domain = new TextEncoder().encode("notarization");
    const domainPtr = this.core.unidpp_alloc(domain.length);
    new Uint8Array(this.core.memory.buffer, domainPtr, domain.length).set(domain);
    const payloadPtr = this.core.unidpp_alloc(payload.length);
    new Uint8Array(this.core.memory.buffer, payloadPtr, payload.length).set(payload);
    const sigPtr = this.core.unidpp_alloc(64);
    const rc = this.core.unidpp_sign_raw(
      seedPtr,
      domainPtr,
      domain.length,
      payloadPtr,
      payload.length,
      sigPtr,
    );
    const signature = hex(new Uint8Array(this.core.memory.buffer, sigPtr, 64).slice());
    [seedPtr, domainPtr, payloadPtr, sigPtr].forEach((ptr, i) =>
      this.core.unidpp_free(ptr, [32, domain.length, payload.length, 64][i]),
    );
    if (rc !== 0) throw new Error(`notarization sign failed (${rc})`);
    return { key_id: this.keyId(seed), suite: "ed25519", signature };
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      for (const op of await this.journal.all()) {
        if (op.op === "snapshot") this.index.push(op.record as SnapshotRecord);
      }
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") return stamped(200, { status: "ok" });
    if (path === "/snapshots" && request.method === "POST") return this.create(request);
    if (path === "/snapshots" && request.method === "GET") {
      return stamped(200, {
        count: this.index.length,
        snapshots: this.index.map((r) => ({
          seq: r.seq,
          snapshot_id: r.snapshot_id,
          passport_id: r.passport_id,
          notarized_at: r.notarized_at,
          anchoring: r.anchoring.status,
        })),
      });
    }
    const one = path.match(/^\/snapshots\/([^/]+)$/);
    if (one && request.method === "GET") return this.access(decodeURIComponent(one[1]));
    return stamped(404, { error: "no such path" });
  }

  private async create(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const passportId = (v.passport_id as string)?.trim();
    const stateHash = (v.state_hash as string)?.trim();
    const logHead = (v.log_head as string)?.trim();
    if (!passportId) return badRequest("`passport_id` is required");
    if (!stateHash || !hexOk(stateHash)) {
      return badRequest("`state_hash` must be 64-char hex");
    }
    if (!logHead || !hexOk(logHead)) {
      return badRequest("`log_head` must be 64-char hex");
    }
    const seq = this.index.length + 1;
    const snapshotId = `snap-${String(seq).padStart(6, "0")}`;
    const notarizedAt = isoNow();
    const submitter = (v.submitter as string | undefined)?.trim() || null;
    const statement = canonicalStatement({
      seq,
      snapshot_id: snapshotId,
      passport_id: passportId,
      state_hash: stateHash,
      log_head: logHead,
      submitter,
      notarized_at: notarizedAt,
    });
    const commitment = sha256Hex(this.core, new TextEncoder().encode(statement));
    const seed = this.seed();
    const sealed = this.seal(seed, new TextEncoder().encode(statement));
    // The anchoring hop: the estate's own LOG DO (in process).
    let anchoring: SnapshotRecord["anchoring"] = {
      status: "unanchored",
      receipt: "the log Durable Object is not bound",
    };
    if (this.env.LOG) {
      const response = await this.env.LOG.fetch(
        new Request("https://do.internal/commitments", {
          method: "POST",
          body: JSON.stringify({
            subject: `urn:unidpp:archive:snapshot:${snapshotId}`,
            commitment,
          }),
        }),
      );
      if (response.status === 201) {
        anchoring = { status: "anchored", receipt: await response.json() };
      } else {
        anchoring = { status: "unanchored", receipt: await response.json() };
      }
    }
    const record: SnapshotRecord = {
      seq,
      snapshot_id: snapshotId,
      passport_id: passportId,
      state_hash: stateHash,
      log_head: logHead,
      submitter,
      notarized_at: notarizedAt,
      commitment,
      signature: sealed,
      anchoring,
    };
    await this.journal.append({ op: "snapshot", record });
    this.index.push(record);
    // The AIP document rides R2.
    const body = JSON.stringify({
      schema: "unidpp-archive/aip/v1",
      service: "unidpp-archive",
      ...record,
      statement,
    });
    if (this.bucket) {
      await this.bucket.put(`snapshots/${snapshotId}.json`, body);
    }
    return stamped(201, record);
  }

  private async access(id: string): Promise<Response> {
    const record = this.index.find((r) => r.snapshot_id === id || String(r.seq) === id);
    if (!record) return stamped(404, { error: `no snapshot \`${id}\`` });
    if (this.bucket) {
      const stored = await this.bucket.get(`snapshots/${record.snapshot_id}.json`);
      if (stored) {
        return stamped(200, JSON.parse(await stored.text()));
      }
    }
    return stamped(200, record);
  }
}

const hexOk = (value: string): boolean => /^[0-9a-fA-F]{64}$/.test(value);
const hex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};
const unhex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((pair) => parseInt(pair, 16)));
const isoNow = (): string => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

// The S4 canonical statement: the snapshot's fields in a fixed key
// order (the byte-exact AIP statement recipe rides the later slices;
// the S4 commitment pins the field content).
function canonicalStatement(fields: Record<string, unknown>): string {
  const keys = [
    "seq",
    "snapshot_id",
    "passport_id",
    "state_hash",
    "log_head",
    "submitter",
    "notarized_at",
  ];
  return keys.map((key) => `${key}=${JSON.stringify(fields[key] ?? null)}`).join("\n");
}
