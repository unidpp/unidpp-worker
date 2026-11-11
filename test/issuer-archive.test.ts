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
});
