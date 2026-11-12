// The issuer on a Durable Object (REARCH R12 S4): passports minted
// through the wasm boundary — the same `Passport::mint` the native
// issuer compiles, included by path — journaled events, point-in-time
// reads. The pack minting and the event signature enforcement ride
// later slices; the journal keeps every event verbatim.

import { journalFor, Journal, JournalOp } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";

export interface PassportRecord {
  document: Record<string, unknown>;
  audit_seq: number;
  /** The bound profile layer (clause 5; the issuer's config
   * vector): id + version + optional effective window, stored
   * verbatim and served beside the document. */
  profiles?: { id: string; version: string; effective_from?: string }[];
}

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

// The mint through the wasm boundary: the same source the native
// issuer compiles. The document rides the module's error buffer
// (64 KiB budget); the length pointer reports the real size.
function mintDocument(
  core: CoreExports,
  identity: string,
  capability: string,
  validFromSecs: number,
): { ok: true; document: Record<string, unknown> } | { ok: false; error: string } {
  const encoder = new TextEncoder();
  const put = (text: string): { ptr: number; len: number } => {
    const bytes = encoder.encode(text);
    const ptr = core.unidpp_alloc(bytes.length);
    new Uint8Array(core.memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };
  const id = put(identity);
  const granularity = put("");
  const cap = put(capability);
  const pid = put("");
  const errPtr = core.unidpp_alloc(1024);
  const lenPtr = core.unidpp_alloc(4);
  const rc = core.unidpp_mint_passport(
    id.ptr,
    id.len,
    granularity.ptr,
    granularity.len,
    cap.ptr,
    cap.len,
    pid.ptr,
    pid.len,
    BigInt(validFromSecs),
    lenPtr,
    errPtr,
  );
  if (rc !== 0) {
    const message = new TextDecoder().decode(
      new Uint8Array(core.memory.buffer, errPtr, 1024).slice().filter((b) => b !== 0),
    );
    return { ok: false, error: message || `the mint failed (${rc})` };
  }
  const length = Number(new DataView(core.memory.buffer, lenPtr).getUint32(0, true));
  const documentText = new TextDecoder().decode(
    new Uint8Array(core.memory.buffer, errPtr, length).slice(),
  );
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(documentText) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "the minted document is not JSON" };
  }
  return { ok: true, document };
}

export class IssuerDO {
  private passports = new Map<string, PassportRecord>();
  private events: JournalOp[] = [];
  private journal: Journal;
  private core: CoreExports;
  private loaded = false;

  constructor(stateOrStorage: unknown) {
    const source =
      (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
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
    if (path === "/healthz") return stamped(200, { status: "ok" });
    if (path === "/passports" && request.method === "POST") return this.mint(request);
    if (path === "/passports" && request.method === "GET") return this.list();
    const event = path.match(/^\/passports\/([^/]+)\/events$/);
    if (event && request.method === "POST") {
      return this.appendEvent(request, decodeURIComponent(event[1]));
    }
    const one = path.match(/^\/passports\/([^/]+)$/);
    if (one && request.method === "GET") return this.getOne(decodeURIComponent(one[1]));
    return stamped(404, { error: "no such path" });
  }

  private apply(op: JournalOp): void {
    if (op.op === "register-passport") {
      const record = op.record as PassportRecord;
      this.passports.set(record.document.passport_id as string, record);
    } else if (op.op === "append-event") {
      const record = this.passports.get(op.passport_id as string);
      if (record) {
        record.document.events = op.events as unknown[];
      }
      this.events.push(op);
    }
  }

  private async mint(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const identity = (v.identity as string)?.trim();
    if (!identity) return badRequest("`identity` is required");
    const capability = (v.capability as string)?.trim() || "silent";
    const validFrom = typeof v.valid_from === "string" ? Date.parse(v.valid_from) : Date.now();
    // The profile layer binds verbatim (the issuer's config
    // vector); the entries must state id and version.
    const rawProfiles = Array.isArray(v.profiles) ? (v.profiles as Record<string, unknown>[]) : [];
    const profiles: NonNullable<PassportRecord["profiles"]> = [];
    for (const entry of rawProfiles) {
      const id = typeof entry["id"] === "string" ? entry["id"].trim() : "";
      const profileVersion = typeof entry["version"] === "string" ? entry["version"].trim() : "";
      if (!id || !profileVersion) {
        return badRequest("each bound profile states `id` and `version`");
      }
      const effectiveFrom = typeof entry["effective_from"] === "string" ? entry["effective_from"] : undefined;
      profiles.push({ id, version: profileVersion, ...(effectiveFrom ? { effective_from: effectiveFrom } : {}) });
    }
    const minted = mintDocument(
      this.core,
      identity,
      capability,
      // The wasm boundary carries no wall clock: the DO supplies it
      // always (SystemTime::now aborts on wasm32-unknown-unknown).
      Math.floor(validFrom / 1000),
    );
    if (!minted.ok) return badRequest(minted.error);
    const passportId = minted.document.passport_id as string;
    if (this.passports.has(passportId)) {
      return badRequest(`passport \`${passportId}\` already exists`);
    }
    const record: PassportRecord = {
      document: minted.document,
      audit_seq: 0,
      ...(profiles.length > 0 ? { profiles } : {}),
    };
    const seq = await this.journal.append({ op: "register-passport", record });
    record.audit_seq = seq;
    this.apply({ op: "register-passport", record });
    return stamped(201, { ...record.document, audit_seq: seq });
  }

  private async appendEvent(request: Request, passportId: string): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const record = this.passports.get(passportId);
    if (!record) return stamped(404, { error: `no passport \`${passportId}\`` });
    const event = v.event ?? v;
    const op: JournalOp = {
      op: "append-event",
      passport_id: passportId,
      event,
    };
    await this.journal.append(op);
    const events = (record.document.events as unknown[] | undefined) ?? [];
    record.document.events = [...events, event];
    this.events.push(op);
    return stamped(201, {
      passport_id: passportId,
      events: record.document.events,
      audit_seq: record.audit_seq,
    });
  }

  private getOne(passportId: string): Response {
    const record = this.passports.get(passportId);
    if (!record) return stamped(404, { error: `no passport \`${passportId}\`` });
    return stamped(200, {
      ...record.document,
      audit_seq: record.audit_seq,
      ...(record.profiles ? { profiles: record.profiles } : {}),
    });
  }

  private list(): Response {
    const passports = [...this.passports.values()].map((record) => ({
      passport_id: record.document.passport_id,
      subject: record.document.product_id,
      audit_seq: record.audit_seq,
    }));
    return stamped(200, { count: passports.length, passports });
  }
}
