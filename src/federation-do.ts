// The federation Durable Object (the adoption audit's cross-border
// gap): the S13 seam as a live surface — a verifier's SIGNED request
// answers under the governing grid policy, the custodian's answer is
// signed in the S13-MESSAGE domain, the authority counter-signs the
// answer's place (XB-7), and the whole choreography replays from the
// journal alone (XB-6). The policy evaluation and every signature
// verification ride the wasm boundary (the s13 and signatif crates'
// own code); this object carries the trust-graph projection (the
// registered peer keys), the policy registry, the segment pins, and
// the journal.

import { journalFor, Journal, JournalOp } from "./journal";
import { CoreExports } from "./wasm";
import { workerCore } from "./mount";
import {
  S13RequestDoc,
  S13ResponseDoc,
  authorityPayloadBytes,
  boundarySeed,
  canonicalRequestBytes,
  canonicalResponseBytes,
  composeLaw,
  coverageCanonical,
  evaluate,
  keyIdFor,
  requestDigest,
  routeCanonical,
  seedPublicKey,
  signS13Message,
  verifyS13Message,
  bytesHex,
  hexBytes,
} from "./s13";

interface SignatureSlotDoc {
  suite: string;
  key_id: string;
  signature: number[] | null;
}

interface SignedRequestDoc {
  request: S13RequestDoc;
  requester: string;
  signature: SignatureSlotDoc;
}

interface SignedResponseDoc {
  response: S13ResponseDoc;
  signature: SignatureSlotDoc;
}

interface NonRepudiableDoc {
  signed: SignedResponseDoc;
  authority: string;
  authority_signature: SignatureSlotDoc;
  sequence: number;
}

type JournalEntryDoc = SignedRequestDoc | SignedResponseDoc | NonRepudiableDoc;

interface NodeRecord {
  node_id: string;
  suite: string;
  public_hex: string;
  key_id: string;
}

interface SegmentPin {
  policy_id: string;
  version: number;
}

interface PolicyRecord {
  policy_id: string;
  version: number;
  document: Record<string, unknown>;
}

const badRequest = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });

const refused = (error: string): Response =>
  new Response(JSON.stringify({ error }), {
    status: 403,
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

const digestKey = (digest: number[] | Uint8Array): string =>
  Array.from(digest).join(",");

export class S13DO {
  private nodes = new Map<string, NodeRecord>();
  private policies = new Map<string, PolicyRecord>();
  private segments = new Map<string, SegmentPin>();
  private entries: { kind: "request" | "response" | "countersigned"; entry: JournalEntryDoc }[] = [];
  private journal: Journal;
  private core: CoreExports;
  private loaded = false;
  private readonly custodianId: string;
  private readonly authorityId: string;
  private readonly custodianSeed: Uint8Array;
  private readonly authoritySeed: Uint8Array;

  constructor(
    stateOrStorage: unknown,
    private readonly env: Record<string, string | undefined> = {},
  ) {
    const source = (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
    this.journal = journalFor(source);
    this.core = workerCore();
    this.custodianId = env.UNIDPP_S13_CUSTODIAN_ID ?? "unidpp-custodian";
    this.authorityId = env.UNIDPP_S13_AUTHORITY_ID ?? "unidpp-authority";
    this.custodianSeed = boundarySeed(this.core, env.UNIDPP_S13_CUSTODIAN_SEED, "UNIDPP-S13/CUSTODIAN-SEED");
    this.authoritySeed = boundarySeed(this.core, env.UNIDPP_S13_AUTHORITY_SEED, "UNIDPP-S13/AUTHORITY-SEED");
  }

  async fetch(request: Request): Promise<Response> {
    if (!this.loaded) {
      for (const op of await this.journal.all()) this.apply(op);
      this.ensureOperatorNodes();
      this.loaded = true;
    }
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/healthz") return stamped(200, { status: "ok" });
    if (path === "/nodes" && request.method === "GET") return this.listNodes();
    if (path === "/nodes" && request.method === "POST") return this.registerNode(request);
    if (path === "/policies" && request.method === "GET") return this.listPolicies();
    if (path === "/policies" && request.method === "POST") return this.registerPolicy(request);
    if (path === "/segments" && request.method === "GET") return this.listSegments();
    if (path === "/segments" && request.method === "POST") return this.pinSegment(request);
    if (path === "/custodian" && request.method === "GET") return this.custodianDocument();
    if (path === "/requests" && request.method === "POST") return this.answer(request);
    if (path === "/countersign" && request.method === "POST") return this.countersign(request);
    if (path === "/journal" && request.method === "GET") return this.replay();
    if (path === "/route/encode" && request.method === "POST") return this.encodeRoute(request);
    if (path === "/coverage/encode" && request.method === "POST") return this.encodeCoverage(request);
    if (path === "/compose" && request.method === "POST") return this.compose(request);
    return stamped(404, { error: "no such path" });
  }

  private apply(op: JournalOp): void {
    switch (op.op) {
      case "node-registered": {
        const record = op.record as NodeRecord;
        this.nodes.set(record.node_id, record);
        break;
      }
      case "policy-registered": {
        const record = op.record as PolicyRecord;
        this.policies.set(`${record.policy_id}@${record.version}`, record);
        break;
      }
      case "segment-pinned": {
        const pin = op.pin as SegmentPin;
        this.segments.set(op.segment as string, pin);
        break;
      }
      case "s13-request":
        this.entries.push({ kind: "request", entry: op.entry as SignedRequestDoc });
        break;
      case "s13-response":
        this.entries.push({ kind: "response", entry: op.entry as SignedResponseDoc });
        break;
      case "s13-countersigned":
        this.entries.push({ kind: "countersigned", entry: op.entry as NonRepudiableDoc });
        break;
    }
  }

  /** The custodian and the policy authority register their seeded
   *  keys, so every journaled answer verifies under this graph. */
  private ensureOperatorNodes(): void {
    for (const [nodeId, seed] of [
      [this.custodianId, this.custodianSeed],
      [this.authorityId, this.authoritySeed],
    ] as const) {
      if (this.nodes.has(nodeId)) continue;
      const publicHex = bytesHex(seedPublicKey(this.core, seed));
      this.appendNode({
        node_id: nodeId,
        suite: "ed25519",
        public_hex: publicHex,
        key_id: keyIdFor(this.core, "ed25519", hexBytes(publicHex)),
      });
    }
  }

  private appendNode(record: NodeRecord): void {
    const op: JournalOp = { op: "node-registered", record };
    this.journal.append(op);
    this.apply(op);
  }

  private listNodes(): Response {
    return stamped(200, { count: this.nodes.size, nodes: [...this.nodes.values()] });
  }

  private async registerNode(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const nodeId = v.node_id ?? v.id;
    const suite = typeof v.suite === "string" ? v.suite : "ed25519";
    const publicHex = typeof v.public_hex === "string" ? v.public_hex : "";
    if (typeof nodeId !== "string" || !nodeId) return badRequest("`node_id` is required");
    const keyBytes = hexBytes(publicHex);
    if (keyBytes.length === 0) return badRequest("`public_hex` is required");
    let keyId: string;
    try {
      keyId = keyIdFor(this.core, suite, keyBytes);
    } catch (e) {
      return badRequest(e instanceof Error ? e.message : "the suite is unknown");
    }
    const record: NodeRecord = { node_id: nodeId, suite, public_hex: publicHex.toLowerCase(), key_id: keyId };
    this.appendNode(record);
    return stamped(201, record);
  }

  private listPolicies(): Response {
    return stamped(200, {
      count: this.policies.size,
      policies: [...this.policies.values()].map((p) => p.document),
    });
  }

  private async registerPolicy(request: Request): Promise<Response> {
    let document: Record<string, unknown>;
    try {
      document = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const policyId = document.policy_id;
    const version = document.version;
    if (typeof policyId !== "string" || !policyId) return badRequest("`policy_id` is required");
    if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
      return badRequest("`version` must be a positive integer");
    }
    const record: PolicyRecord = { policy_id: policyId, version, document };
    const op: JournalOp = { op: "policy-registered", record };
    await this.journal.append(op);
    this.apply(op);
    return stamped(201, { policy_id: policyId, version, registered: true });
  }

  private listSegments(): Response {
    return stamped(200, {
      count: this.segments.size,
      segments: [...this.segments.entries()].map(([segment, pin]) => ({ segment, ...pin })),
    });
  }

  private async pinSegment(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const segment = v.segment;
    const policyId = v.policy_id;
    const version = v.version;
    if (typeof segment !== "string" || !segment) return badRequest("`segment` is required");
    if (typeof policyId !== "string" || !policyId) return badRequest("`policy_id` is required");
    if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
      return badRequest("`version` must be a positive integer");
    }
    if (!this.policies.has(`${policyId}@${version}`)) {
      return badRequest(`no policy \`${policyId}\` version ${version} is registered`);
    }
    const pin: SegmentPin = { policy_id: policyId, version };
    const op: JournalOp = { op: "segment-pinned", segment, pin };
    await this.journal.append(op);
    this.apply(op);
    return stamped(201, { segment, ...pin, pinned: true });
  }

  private custodianDocument(): Response {
    const custodian = this.nodes.get(this.custodianId);
    const authority = this.nodes.get(this.authorityId);
    return stamped(200, {
      custodian: this.custodianId,
      key_id: custodian?.key_id ?? null,
      public_hex: custodian?.public_hex ?? null,
      authority: this.authorityId,
      authority_key_id: authority?.key_id ?? null,
      authority_public_hex: authority?.public_hex ?? null,
    });
  }

  /** The seam's answer: verify the signed request under the
   *  registered graph, evaluate the governing policy on the
   *  boundary, sign the answer, journal both. */
  private async answer(request: Request): Promise<Response> {
    let signed: SignedRequestDoc;
    try {
      signed = (await request.json()) as SignedRequestDoc;
    } catch {
      return badRequest("invalid JSON body");
    }
    if (!signed?.request || !signed.requester || !signed.signature) {
      return badRequest("the signed request needs `request`, `requester` and `signature`");
    }
    const verified = this.verifyRequest(signed);
    if (!verified.ok) return refused(verified.error);
    const digest = requestDigest(this.core, signed.request);
    const response = this.evaluateFor(signed.request);
    const bodyBytes = canonicalResponseBytes(response);
    const signatureBytes = signS13Message(this.core, this.custodianSeed, bodyBytes);
    const signedResponse: SignedResponseDoc = {
      response,
      signature: {
        suite: "ed25519",
        key_id: this.nodes.get(this.custodianId)!.key_id,
        signature: [...signatureBytes],
      },
    };
    await this.journal.append({ op: "s13-request", entry: signed });
    await this.journal.append({ op: "s13-response", entry: signedResponse });
    this.entries.push({ kind: "request", entry: signed });
    this.entries.push({ kind: "response", entry: signedResponse });
    return stamped(201, {
      request_digest: bytesHex(digest),
      signed_response: signedResponse,
    });
  }

  /** The graph check: the signature must resolve to the DECLARED
   *  requester's registered key (a valid signature from any other
   *  node is not this request). */
  private verifyRequest(signed: SignedRequestDoc): { ok: true } | { ok: false; error: string } {
    const node = this.nodes.get(signed.requester);
    if (!node) return { ok: false, error: `s13 requester \`${signed.requester}\` has no such node` };
    if (node.key_id !== signed.signature.key_id) {
      return { ok: false, error: `s13 requester \`${signed.requester}\` has no such key` };
    }
    const verifies = verifyS13Message(
      this.core,
      signed.signature.suite,
      hexBytes(node.public_hex),
      canonicalRequestBytes(signed.request),
      new Uint8Array(signed.signature.signature ?? []),
    );
    if (!verifies) {
      return { ok: false, error: `the request's signature does not verify under \`${signed.requester}\`` };
    }
    return { ok: true };
  }

  /** The policy evaluation: the segment's pin selects the governing
   *  policy; no pin (or a missing version) answers a stated denial —
   *  never silent, never an error code. */
  private evaluateFor(request: S13RequestDoc): S13ResponseDoc {
    const pin = this.segments.get(request.segment);
    const digest = [...requestDigest(this.core, request)];
    if (!pin) {
      return {
        request_digest: digest,
        outcome: { outcome: "deny", reason: `no governing policy is pinned for segment \`${request.segment}\`` },
        governing_policy: "",
        governing_policy_version: 0,
        custodian: this.custodianId,
      };
    }
    const policy = this.policies.get(`${pin.policy_id}@${pin.version}`);
    if (!policy) {
      return {
        request_digest: digest,
        outcome: {
          outcome: "deny",
          reason: `the pinned policy \`${pin.policy_id}\` version ${pin.version} is not registered`,
        },
        governing_policy: pin.policy_id,
        governing_policy_version: pin.version,
        custodian: this.custodianId,
      };
    }
    const outcome = evaluate(this.core, JSON.stringify(policy.document), JSON.stringify(request), this.custodianId);
    if (!outcome.ok) {
      return {
        request_digest: digest,
        outcome: { outcome: "deny", reason: outcome.error },
        governing_policy: pin.policy_id,
        governing_policy_version: pin.version,
        custodian: this.custodianId,
      };
    }
    return outcome.response;
  }

  /** The non-repudiable answer (XB-7): the policy authority
   *  counter-signs the custodian's answer and its place in the
   *  per-(subject, custodian) sequence. */
  private async countersign(request: Request): Promise<Response> {
    let v: Record<string, unknown>;
    try {
      v = (await request.json()) as Record<string, unknown>;
    } catch {
      return badRequest("invalid JSON body");
    }
    const digestHex0 = typeof v.request_digest === "string" ? v.request_digest : "";
    const digest = hexBytes(digestHex0);
    if (digest.length !== 32) return badRequest("`request_digest` must be 32 bytes of hex");
    const answered = [...this.entries]
      .reverse()
      .find(
        (e): e is { kind: "response"; entry: SignedResponseDoc } =>
          e.kind === "response" && digestKey((e.entry as SignedResponseDoc).response.request_digest) === digestKey([...digest]),
      );
    if (!answered) return stamped(404, { error: "no journaled answer carries that request digest" });
    const signed = answered.entry as SignedResponseDoc;
    const subject = this.subjectOf([...digest]);
    if (subject === null) return stamped(404, { error: "no journaled request carries that digest" });
    const sequence = this.nextSequence(subject, signed.response.custodian);
    const payload = authorityPayloadBytes(signed.response, sequence);
    const signatureBytes = signS13Message(this.core, this.authoritySeed, payload);
    const nonRepudiable: NonRepudiableDoc = {
      signed,
      authority: this.authorityId,
      authority_signature: {
        suite: "ed25519",
        key_id: this.nodes.get(this.authorityId)!.key_id,
        signature: [...signatureBytes],
      },
      sequence,
    };
    await this.journal.append({ op: "s13-countersigned", entry: nonRepudiable });
    this.entries.push({ kind: "countersigned", entry: nonRepudiable });
    return stamped(201, nonRepudiable);
  }

  private subjectOf(digest: number[]): string | null {
    for (const e of this.entries) {
      if (e.kind !== "request") continue;
      const signed = e.entry as SignedRequestDoc;
      if (digestKey(requestDigest(this.core, signed.request)) === digestKey(digest)) {
        return signed.request.subject;
      }
    }
    return null;
  }

  private nextSequence(subject: string, custodian: string): number {
    let last = 0;
    for (const e of this.entries) {
      if (e.kind !== "countersigned") continue;
      const nr = e.entry as NonRepudiableDoc;
      if (nr.signed.response.custodian !== custodian) continue;
      const digest = nr.signed.response.request_digest;
      const request = this.entries.find(
        (r) => r.kind === "request" && digestKey(requestDigest(this.core, (r.entry as SignedRequestDoc).request)) === digestKey(digest),
      );
      if (request && (request.entry as SignedRequestDoc).request.subject === subject) {
        last = Math.max(last, nr.sequence);
      }
    }
    return last + 1;
  }

  /** The choreography replay (XB-6): every entry verifies under the
   *  registered graph, every answer binds to a journaled request,
   *  every counter-signature sits at its exact monotone place. The
   *  decisions come back in journal sequence; a failure is the
   *  tampering evidence itself. */
  private replay(): Response {
    const decisions: Record<string, unknown>[] = [];
    const seenRequests = new Set<string>();
    const sequences = new Map<string, number>();
    let index = 0;
    for (const { kind, entry } of this.entries) {
      index += 1;
      if (kind === "request") {
        const signed = entry as SignedRequestDoc;
        const check = this.verifyRequest(signed);
        if (!check.ok) return this.replayRefused(index, check.error);
        seenRequests.add(digestKey(requestDigest(this.core, signed.request)));
        continue;
      }
      if (kind === "response") {
        const signed = entry as SignedResponseDoc;
        const check = this.verifyResponse(signed);
        if (check !== true) return this.replayRefused(index, check);
        if (!seenRequests.has(digestKey(signed.response.request_digest))) {
          return this.replayRefused(index, "journal replay: an answer is bound to no journaled request");
        }
        decisions.push(this.decisionOf(signed.response));
        continue;
      }
      const nr = entry as NonRepudiableDoc;
      if (!seenRequests.has(digestKey(nr.signed.response.request_digest))) {
        return this.replayRefused(index, "journal replay: an answer is bound to no journaled request");
      }
      const subject = this.subjectOf(nr.signed.response.request_digest) ?? "";
      const key = `${subject}|${nr.signed.response.custodian}`;
      const expected = (sequences.get(key) ?? 0) + 1;
      if (nr.sequence !== expected) {
        return this.replayRefused(
          index,
          `journal replay: s13 non-repudiation: stale sequence ${nr.sequence} (expected ${expected}) — a replayed answer`,
        );
      }
      const custodianOk = this.verifyResponse(nr.signed);
      if (custodianOk !== true) return this.replayRefused(index, custodianOk);
      const authorityNode = this.nodes.get(nr.authority);
      if (!authorityNode || authorityNode.key_id !== nr.authority_signature.key_id) {
        return this.replayRefused(index, `s13 authority \`${nr.authority}\` has no such key`);
      }
      const authorityVerifies = verifyS13Message(
        this.core,
        nr.authority_signature.suite,
        hexBytes(authorityNode.public_hex),
        authorityPayloadBytes(nr.signed.response, nr.sequence),
        new Uint8Array(nr.authority_signature.signature ?? []),
      );
      if (!authorityVerifies) {
        return this.replayRefused(index, `the authority's counter-signature does not verify under \`${nr.authority}\``);
      }
      sequences.set(key, nr.sequence);
      decisions.push(this.decisionOf(nr.signed.response));
    }
    return stamped(200, {
      side: "custodian",
      count: this.entries.length,
      entries: this.entries.map((e) => e.entry),
      decisions,
    });
  }

  private verifyResponse(signed: SignedResponseDoc): true | string {
    const node = this.nodes.get(signed.response.custodian);
    if (!node) return `s13 custodian \`${signed.response.custodian}\` has no such node`;
    if (node.key_id !== signed.signature.key_id) {
      return `s13 custodian \`${signed.response.custodian}\` has no such key`;
    }
    const verifies = verifyS13Message(
      this.core,
      signed.signature.suite,
      hexBytes(node.public_hex),
      canonicalResponseBytes(signed.response),
      new Uint8Array(signed.signature.signature ?? []),
    );
    return verifies ? true : "the response's signature does not verify under the custodian";
  }

  private replayRefused(index: number, error: string): Response {
    return stamped(409, { valid: false, entry: index, error });
  }

  private decisionOf(response: S13ResponseDoc): Record<string, unknown> {
    return {
      request_digest_hex: bytesHex(new Uint8Array(response.request_digest)),
      outcome: response.outcome.outcome,
      governing_policy: response.governing_policy,
      governing_policy_version: response.governing_policy_version,
    };
  }

  /** The dossier encoders (SI-11/XB-8) and the composition law
   *  (SI-10), served through the crate's own code on the boundary:
   *  a route's steps or a coverage report ride as JSON, the
   *  canonical bytes and the digest come back — the same identities
   *  the corpus's fixtures pin. */
  private async encodeRoute(request: Request): Promise<Response> {
    let v: { steps?: unknown };
    try {
      v = (await request.json()) as { steps?: unknown };
    } catch {
      return badRequest("invalid JSON body");
    }
    if (!Array.isArray(v?.steps)) return badRequest("`steps` is required (a JSON array)");
    const outcome = routeCanonical(this.core, v.steps as never);
    if (!outcome.ok) return badRequest(outcome.error);
    return stamped(200, outcome.document);
  }

  private async encodeCoverage(request: Request): Promise<Response> {
    let v: { report?: unknown };
    try {
      v = (await request.json()) as { report?: unknown };
    } catch {
      return badRequest("invalid JSON body");
    }
    if (!v?.report || typeof v.report !== "object") return badRequest("`report` is required");
    const outcome = coverageCanonical(this.core, v.report);
    if (!outcome.ok) return badRequest(outcome.error);
    return stamped(200, outcome.document);
  }

  private async compose(request: Request): Promise<Response> {
    let v: { vector?: unknown; policy_cap?: number };
    try {
      v = (await request.json()) as { vector?: unknown; policy_cap?: number };
    } catch {
      return badRequest("invalid JSON body");
    }
    if (!v?.vector || typeof v.vector !== "object") return badRequest("`vector` is required (the six layers)");
    if (typeof v.policy_cap !== "number" || !Number.isInteger(v.policy_cap) || v.policy_cap < 0) {
      return badRequest("`policy_cap` must be a non-negative integer");
    }
    const outcome = composeLaw(this.core, v.vector, v.policy_cap);
    if (!outcome.ok) return badRequest(outcome.error);
    return stamped(200, outcome.composition);
  }
}
