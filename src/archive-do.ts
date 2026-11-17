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
  idFromName?(name: string): unknown;
  get?(id: unknown): { fetch(request: Request): Promise<Response> };
  fetch?(request: Request): Promise<Response>;
}

export class ArchiveDO {
  private journal: Journal;
  private core: ReturnType<typeof workerCore>;
  private index: SnapshotRecord[] = [];
  private loaded = false;
  private bucket: Bucket | null;

  constructor(
    stateOrStorage: unknown,
    private readonly env: {
      ARCHIVE_BUCKET?: Bucket;
      LOG?: LogNamespace;
      UNIDPP_ARCHIVE_SIGN_SEED?: string;
      UNIDPP_ARCHIVE_ADMIN_TOKEN?: string;
    },
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

  // The notary public key (what verifiers pin): the 32 Ed25519
  // bytes the wasm boundary derives from the seed.
  private publicKey(seed: Uint8Array): Uint8Array {
    const seedPtr = this.core.unidpp_alloc(32);
    new Uint8Array(this.core.memory.buffer, seedPtr, 32).set(seed);
    const outPtr = this.core.unidpp_alloc(32);
    this.core.unidpp_head_public(seedPtr, outPtr);
    const bytes = new Uint8Array(this.core.memory.buffer, outPtr, 32).slice();
    this.core.unidpp_free(seedPtr, 32);
    this.core.unidpp_free(outPtr, 32);
    return bytes;
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
    if (path === "/" && request.method === "GET") return this.discovery();
    if (path === "/keyring" && request.method === "GET") return this.keyringDocument();
    if (path === "/admin/log" && request.method === "GET") return this.adminLog(request);
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

  // The bearer guard (the native require_admin): POST /snapshots and
  // /admin/log refuse without the token, when one is configured.
  private requireAdmin(request: Request): Response | null {
    const token = this.env.UNIDPP_ARCHIVE_ADMIN_TOKEN;
    if (!token) return null;
    const got = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/, "");
    if (got === token) return null;
    return stamped(401, { error: "unauthorized" });
  }

  // The discovery document: the service identity, the OAIS mapping,
  // the notarization recipe, the anchoring semantics, the storage
  // layout and the entry points (the native module root's own).
  private discovery(): Response {
    const anchored = Boolean(this.env.LOG);
    return stamped(200, {
      anchoring: {
        fallback:
          "an unreachable or refusing log degrades to status=unanchored with the reason recorded; the snapshot remains notarized",
        how: "POST {UNIDPP_LOG_URL}/commitments with {subject: urn:unidpp:archive:snapshot:<id>, commitment: sha256(core statement bytes)}",
        journalled:
          "receipt id, log id, tree size, root, logged_at, and the verbatim receipt ride the snapshot's provenance and the audit journal",
        when: "UNIDPP_LOG_URL points at a reachable unidpp-log instance",
      },
      anchoring_enabled: anchored,
      as_of: {
        listing_rule: "a snapshot is listed at instant T when notarized_at <= T",
        point_in_time_cache:
          "responses to ?at=... carry cache-control: public, max-age=86400, immutable",
        query_parameter: "at (alias: asof)",
        response_header: "x-as-of",
      },
      auth: "POST /snapshots and /admin/log require a Bearer token when UNIDPP_ARCHIVE_ADMIN_TOKEN is set",
      build_id: "dev",
      description:
        "UniDPP Tier-C notarized archive: as-of snapshot packs with OAIS-style metadata, Ed25519 notarization, optional transparency-log anchoring, byte-identical re-serving.",
      endpoints: {
        admin_log: "GET /admin/log?limit=&offset=",
        discovery: "GET /",
        health: "GET /healthz",
        ingest: "POST /snapshots",
        keyring: "GET /keyring",
        listing: "GET /snapshots?passport_id=&at=",
        snapshot: "GET /snapshots/{id}",
      },
      notarization: {
        adapter_note: ADAPTER_NOTE,
        domain: "tree-head",
        keyring_endpoint: "/keyring",
        statement_recipe: [
          'core = CanonicalWriter: str("unidpp-archive"), str(snapshot_id), u64(seq), str(oais.information_package.passport_id), hash(state_hash), hash(log_head), i64(as_of.secs)',
          'if oais.provenance.anchoring.status == "anchored": append u32(1), str(anchoring.log_id), u64(anchoring.receipt_id), u64(anchoring.tree_size), hash(anchoring.root); else append u32(0)',
          "verify: SignatureSlot{suite: ed25519, key_id: oais.provenance.signing.key_id, signature: hex(oais.provenance.signature)}.verify(SigningDomain::TreeHead, statement, public from /keyring)",
          "commitment check: sha256(core) == oais.information_package.commitment (and == oais.provenance.receipt.commitment when anchored)",
        ],
        suite: "ed25519",
      },
      oais: {
        mapping: {
          access: "GET /snapshots/{id} — re-serves the AIP byte-identically (access never changes the AIP)",
          administration: "GET /keyring, GET /admin/log, Bearer-guarded ingest",
          archival_storage:
            "the JSONL journal (source of truth) + one AIP file per snapshot under the snapshot directory",
          data_management: "GET /snapshots?passport_id=&at= — the as-of catalogue",
          document_sections: {
            "oais.information_package":
              "the AIP content: passport state, log head, the as_of instant, the commitment and statement digests",
            "oais.provenance":
              "the PDI: notarization (key id, signature), anchoring outcome and the verbatim log receipt",
            "oais.submission":
              "the SIP: submitter, submitted_at, and the submitted {passport_id, state_hash, log_head, state_size}",
          },
          ingest:
            "POST /snapshots: validate, timestamp, notarize (sign), optionally anchor into the transparency log",
          producer:
            "the issuer submitting {passport_id, state_hash, log_head} (POST /snapshots body = the SIP)",
        },
        profile: "ISO 14721 (OAIS) simplified for digital product passports",
      },
      schema: "unidpp-archive/snapshot/1",
      service: "unidpp-archive",
      storage: {
        journal:
          "append-only JSONL (UNIDPP_ARCHIVE_STATE_FILE); replay on start with sequence, digest and torn-tail checks",
        re_serve:
          "GET /snapshots/{id} re-renders from the journaled record — byte-identical by construction, pinned by the strong ETag",
        snapshot_store:
          "one JSON file per snapshot (UNIDPP_ARCHIVE_SNAPSHOT_DIR); verified against the journal on start, re-materialized when missing, mismatch is a hard error",
      },
      version: "0.1.0",
    });
  }

  // The notary keyring a verifier pins (the native /keyring: the
  // mode, the suite, the key id, the public anchor, the verification
  // recipe and, in seeded-dev mode, the warning).
  private keyringDocument(): Response {
    const envSeed = this.env.UNIDPP_ARCHIVE_SIGN_SEED;
    const envKey = Boolean(envSeed && /^[0-9a-fA-F]{64}$/.test(envSeed.trim()));
    const seed = this.seed();
    const body: Record<string, unknown> = {
      adapter_note: ADAPTER_NOTE,
      as_of: isoNow(),
      domain: "tree-head",
      key_id: this.keyId(seed),
      mode: envKey ? "env-key" : "seeded-dev",
      public: hex(this.publicKey(seed)),
      public_len: 32,
      role: "notary",
      suite: "ed25519",
      verification:
        "Every snapshot document embeds oais.provenance.signature: Ed25519 over the canonical statement bytes in the tree-head domain. Rebuild the bytes per the discovery document's notarization recipe and verify with unidpp_signatif SignatureSlot::verify against this `public` anchor.",
    };
    if (!envKey) {
      // The dev seed label this keyring derives from, and the mode
      // warning (the native's seeded-dev posture).
      body.dev_seed = "UNIDPP-ARCHIVE/NOTARY-SEED";
      body.warning =
        "seeded-dev mode is for development only; production deployments must use env-key mode";
    }
    return stamped(200, body);
  }

  // The audit view of the journal (the native /admin/log): the
  // windowed records, each carrying its body digest.
  private adminLog(request: Request): Response {
    const deny = this.requireAdmin(request);
    if (deny) return deny;
    const params = new URL(request.url).searchParams;
    const nonNegative = (raw: string | null): number | null => {
      if (raw === null) return null;
      const n = Number(raw);
      return Number.isInteger(n) && n >= 0 ? n : null;
    };
    const limit = Math.min(nonNegative(params.get("limit")) ?? 100, 10_000);
    const offset = nonNegative(params.get("offset")) ?? 0;
    const slice = this.index.slice(offset, offset + limit).map((r) => this.auditRecord(r));
    return stamped(200, {
      count: slice.length,
      limit,
      offset,
      records: slice,
      total: this.index.length,
    });
  }

  // One journal record's audit form: the snapshot's fields with the
  // digests of the exact stored body (recomputed — the same bytes
  // create() wrote).
  private auditRecord(record: SnapshotRecord): Record<string, unknown> {
    const statement = canonicalStatement({
      seq: record.seq,
      snapshot_id: record.snapshot_id,
      passport_id: record.passport_id,
      state_hash: record.state_hash,
      log_head: record.log_head,
      submitter: record.submitter,
      notarized_at: record.notarized_at,
    });
    const digest = sha256Hex(this.core, new TextEncoder().encode(aipBody(record, statement)));
    return {
      anchoring: record.anchoring,
      body_digest: digest,
      body_sha256: digest,
      key_id: record.signature.key_id,
      log_head: record.log_head,
      notarized_at: record.notarized_at,
      passport_id: record.passport_id,
      seq: record.seq,
      signature: record.signature.signature,
      snapshot_id: record.snapshot_id,
      state_hash: record.state_hash,
      state_size: null,
      submitter: record.submitter,
    };
  }

  private async create(request: Request): Promise<Response> {
    const deny = this.requireAdmin(request);
    if (deny) return deny;
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
      // workerd hands the namespace; the tests hand a LogDO itself
      // (the in-process bridge in both worlds).
      const log = this.env.LOG;
      const logStub = log.get
        ? log.get(log.idFromName!("estate"))
        : { fetch: log.fetch!.bind(log) };
      const response = await logStub.fetch(
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
    const body = aipBody(record, statement);
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

// The notarization's adapter note (the model's own, verbatim): the
// tree-head slot is the documented adaptation, shared with
// unidpp-trust.
const ADAPTER_NOTE =
  "SIGNATIF has no archival-notarization domain; tree-head (the operator's signed statement of state, used for transparency-log signed tree heads) is the closest documented adaptation — the same adapter note as unidpp-trust. signatif's HistoricalStamp domain ('a notarized historical verification stamp') is the semantically exact slot; adoption is deferred to the 19-signatif-spec-sync divergence register. The signature covers the canonical statement bytes and is embedded in the document so the AIP is self-verifying.";

// The exact stored AIP bytes (create() writes them; the audit view
// recomputes the digest over the same recipe).
const aipBody = (record: SnapshotRecord, statement: string): string =>
  JSON.stringify({
    schema: "unidpp-archive/aip/v1",
    service: "unidpp-archive",
    ...record,
    statement,
  });

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
