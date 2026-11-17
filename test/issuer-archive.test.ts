// S4's gates (REARCH R12): the issuer mints through the wasm
// boundary — the same Passport::mint source the native issuer
// compiles — journals events, and reads point-in-time; the archive
// notarizes snapshots with the wasm seal, anchors them into the
// estate's own log DO in process, and stores the AIP documents in
// the bucket.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";
import { ArchiveDO } from "../src/archive-do";
import { LogDO } from "../src/log-do";

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

const bucketStore = new Map<string, string>();
const bucket = {
  put: async (key: string, value: string) => void bucketStore.set(key, value),
  get: async (key: string) => {
    const value = bucketStore.get(key);
    return value ? { text: async () => value } : null;
  },
};

const serve = (registry: IssuerDO | ArchiveDO | LogDO, path: string, init?: RequestInit): Promise<Response> =>
  registry.fetch(new Request(`https://do.internal${path}`, init));

describe("the issuer Durable Object", () => {
  it("mints through the wasm boundary and journals events", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await serve(issuer, "/passports", {
      method: "POST",
      body: JSON.stringify({ identity: "https://product.example.org/s4-parity" }),
    });
    expect(minted.status).toBe(201);
    const body = (await minted.json()) as Record<string, unknown>;
    expect(body.passport_id).toBeTruthy();
    expect(body.capability).toBe("silent");
    expect(body.audit_seq).toBe(1);

    const event = await serve(issuer, `/passports/${body.passport_id}/events`, {
      method: "POST",
      body: JSON.stringify({ event: { type: "state-change", to: "in-use" } }),
    });
    expect(event.status).toBe(201);
    const withEvents = (await event.json()) as { events: unknown[] };
    expect(withEvents.events.length).toBe(1);

    const read = await serve(issuer, `/passports/${body.passport_id}`);
    expect(read.status).toBe(200);
    const document = (await read.json()) as { events: unknown[]; passport_id: string };
    expect(document.events.length).toBe(1);
    const listing = (await (await serve(issuer, "/passports")).json()) as { count: number };
    expect(listing.count).toBe(1);
    const absent = await serve(issuer, "/passports/no-such-passport");
    expect(absent.status).toBe(404);
    const noIdentity = await serve(issuer, "/passports", {
      method: "POST",
      body: JSON.stringify({}),
    });
    expect(noIdentity.status).toBe(400);
  });

  it("rejects an identity the identifier grammar refuses", async () => {
    const issuer = new IssuerDO(storage());
    const minted = await serve(issuer, "/passports", {
      method: "POST",
      body: JSON.stringify({ identity: "   " }),
    });
    expect(minted.status).toBe(400);
  });
});

describe("the archive Durable Object with the log bridge", () => {
  it("notarizes, anchors in process, and stores the AIP in the bucket", async () => {
    const log = new LogDO(storage(), {});
    const archive = new ArchiveDO(storage(), { ARCHIVE_BUCKET: bucket, LOG: log });
    const response = await serve(archive, "/snapshots", {
      method: "POST",
      body: JSON.stringify({
        passport_id: "urn:unidpp:passport:s4",
        state_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        log_head: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        submitter: "s4-test",
      }),
    });
    expect(response.status).toBe(201);
    const record = (await response.json()) as {
      seq: number;
      snapshot_id: string;
      commitment: string;
      signature: { suite: string; key_id: string; signature: string };
      anchoring: { status: string };
    };
    expect(record.seq).toBe(1);
    expect(record.signature.suite).toBe("ed25519");
    expect(record.signature.signature.length).toBe(128);
    expect(record.anchoring.status).toBe("anchored");
    expect(bucketStore.has(`snapshots/${record.snapshot_id}.json`)).toBe(true);

    const listing = (await (await serve(archive, "/snapshots")).json()) as { count: number };
    expect(listing.count).toBe(1);
    const read = await serve(archive, `/snapshots/${record.snapshot_id}`);
    expect(read.status).toBe(200);
    const stored = (await read.json()) as { statement: string; commitment: string };
    expect(stored.statement).toContain("passport_id");
    expect(stored.commitment).toBe(record.commitment);
  });

  it("states the unanchored degrade when the log is not bound", async () => {
    const archive = new ArchiveDO(storage(), { ARCHIVE_BUCKET: bucket });
    const response = await serve(archive, "/snapshots", {
      method: "POST",
      body: JSON.stringify({
        passport_id: "urn:unidpp:passport:s4-b",
        state_hash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        log_head: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      }),
    });
    expect(response.status).toBe(201);
    const record = (await response.json()) as { anchoring: { status: string } };
    expect(record.anchoring.status).toBe("unanchored");
  });

  it("refuses malformed hashes", async () => {
    const archive = new ArchiveDO(storage(), {});
    const refused = await serve(archive, "/snapshots", {
      method: "POST",
      body: JSON.stringify({
        passport_id: "urn:unidpp:passport:s4-c",
        state_hash: "not-hex",
        log_head: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      }),
    });
    expect(refused.status).toBe(400);
  });

  // The native module root: the discovery document the bare /archive
  // prefix serves (the OAIS mapping, the notarization recipe, the
  // anchoring posture, the entry points).
  it("serves the discovery document at the module root", async () => {
    const anchored = new ArchiveDO(storage(), { LOG: new LogDO(storage(), {}) });
    const served = await serve(anchored, "/");
    expect(served.status).toBe(200);
    expect(served.headers.get("x-as-of")).toBeTruthy();
    const doc = (await served.json()) as {
      service?: string;
      anchoring_enabled?: boolean;
      schema?: string;
      auth?: string;
      endpoints?: Record<string, string>;
      notarization?: { domain?: string; suite?: string; adapter_note?: string };
      oais?: { profile?: string };
    };
    expect(doc.service).toBe("unidpp-archive");
    expect(doc.anchoring_enabled).toBe(true);
    expect(doc.schema).toBe("unidpp-archive/snapshot/1");
    expect(doc.auth).toContain("UNIDPP_ARCHIVE_ADMIN_TOKEN");
    expect(doc.endpoints?.admin_log).toBe("GET /admin/log?limit=&offset=");
    expect(doc.endpoints?.keyring).toBe("GET /keyring");
    expect(doc.notarization?.domain).toBe("tree-head");
    expect(doc.notarization?.suite).toBe("ed25519");
    expect(doc.notarization?.adapter_note).toContain("tree-head");
    expect(doc.oais?.profile).toContain("ISO 14721");
    // The unbound log is the stated degrade (the native's
    // anchoring_enabled posture).
    const detached = new ArchiveDO(storage(), {});
    const bare = (await (await serve(detached, "/")).json()) as { anchoring_enabled?: boolean };
    expect(bare.anchoring_enabled).toBe(false);
  });

  // The notary keyring a verifier pins: the seeded-dev mode by
  // default (with the stated warning), the env seed for production
  // material.
  it("serves the notary keyring", async () => {
    const archive = new ArchiveDO(storage(), {});
    const served = await serve(archive, "/keyring");
    expect(served.status).toBe(200);
    const body = (await served.json()) as {
      mode?: string;
      role?: string;
      suite?: string;
      key_id?: string;
      public?: string;
      public_len?: number;
      domain?: string;
      dev_seed?: string;
      warning?: string;
      as_of?: string;
      adapter_note?: string;
      verification?: string;
    };
    expect(body.mode).toBe("seeded-dev");
    expect(body.role).toBe("notary");
    expect(body.suite).toBe("ed25519");
    expect(body.key_id).toMatch(/^k-/);
    expect(body.public).toMatch(/^[0-9a-f]{64}$/);
    expect(body.public_len).toBe(32);
    expect(body.domain).toBe("tree-head");
    expect(body.dev_seed).toBeTruthy();
    expect(body.warning).toContain("seeded-dev");
    expect(body.as_of).toBeTruthy();
    expect(body.verification).toContain("SignatureSlot::verify");
    // The env seed is the env-key mode: the warning is withdrawn and
    // the anchor re-derives from the declared material.
    const envArchive = new ArchiveDO(storage(), {
      UNIDPP_ARCHIVE_SIGN_SEED:
        "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee",
    });
    const envServed = await serve(envArchive, "/keyring");
    const envBody = (await envServed.json()) as {
      mode?: string;
      warning?: string;
      dev_seed?: string;
      public?: string;
    };
    expect(envBody.mode).toBe("env-key");
    expect(envBody.warning).toBeUndefined();
    expect(envBody.dev_seed).toBeUndefined();
    expect(envBody.public).not.toBe(body.public);
  });

  // The audit view of the journal: the windowed records with their
  // body digests, the limit/offset echo, and the bearer guard.
  it("serves the admin log with the bearer guard", async () => {
    const archive = new ArchiveDO(storage(), { ARCHIVE_BUCKET: bucket });
    for (const [passport, hash] of [
      ["urn:unidpp:passport:audit-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      ["urn:unidpp:passport:audit-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    ] as const) {
      const created = await serve(archive, "/snapshots", {
        method: "POST",
        body: JSON.stringify({ passport_id: passport, state_hash: hash, log_head: hash }),
      });
      expect(created.status).toBe(201);
    }
    const full = (await (await serve(archive, "/admin/log")).json()) as {
      count?: number;
      total?: number;
      limit?: number;
      offset?: number;
      records?: {
        seq: number;
        snapshot_id: string;
        state_size: unknown;
        signature: string;
        key_id: string;
        body_sha256: string;
        body_digest: string;
        anchoring: unknown;
      }[];
    };
    expect(full.count).toBe(2);
    expect(full.total).toBe(2);
    expect(full.limit).toBe(100);
    expect(full.offset).toBe(0);
    expect(full.records?.[0].seq).toBe(1);
    expect(full.records?.[0].body_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(full.records?.[0].body_digest).toBe(full.records?.[0].body_sha256);
    expect(full.records?.[0].signature).toMatch(/^[0-9a-f]{128}$/);
    expect(full.records?.[0].key_id).toMatch(/^k-/);
    expect(full.records?.[0].state_size).toBeNull();
    expect(full.records?.[0].anchoring).toBeTruthy();
    // The window: limit and offset echo, journal order preserved.
    const windowed = (await (await serve(archive, "/admin/log?limit=1&offset=1")).json()) as {
      count?: number;
      limit?: number;
      offset?: number;
      records?: { seq: number }[];
    };
    expect(windowed.count).toBe(1);
    expect(windowed.limit).toBe(1);
    expect(windowed.offset).toBe(1);
    expect(windowed.records?.[0].seq).toBe(2);
    // The guard: a configured token refuses the bare request and
    // admits the bearer.
    const guarded = new ArchiveDO(storage(), { UNIDPP_ARCHIVE_ADMIN_TOKEN: "op-secret" });
    const denied = await serve(guarded, "/admin/log");
    expect(denied.status).toBe(401);
    const denial = (await denied.json()) as { error?: string };
    expect(denial.error).toBe("unauthorized");
    const admitted = await serve(guarded, "/admin/log", {
      headers: { authorization: "Bearer op-secret" },
    });
    expect(admitted.status).toBe(200);
    // Ingest is guarded the same way.
    const bareIngest = await serve(guarded, "/snapshots", {
      method: "POST",
      body: JSON.stringify({
        passport_id: "urn:unidpp:passport:audit-c",
        state_hash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        log_head: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      }),
    });
    expect(bareIngest.status).toBe(401);
  });
});
