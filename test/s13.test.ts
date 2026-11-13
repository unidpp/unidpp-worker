// The S13 federation gates (the audit's cross-border gap): the
// canonical encoders reproduce the golden fixtures byte-identically
// (the request digest, the response's canonical form), the F2
// signed-exchange vector verifies through the wasm boundary's own
// slot verify (the key ids Annex B pins), and the federation DO
// answers a foreign signed request under the governing policy,
// journals the choreography, replays it, and counter-signs the
// answer's place.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import nodeCrypto from "node:crypto";
import { CoreExports } from "../src/wasm";
import { digestHex } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { S13DO } from "../src/federation-do";
import {
  S13RequestDoc,
  authorityPayloadBytes,
  canonicalRequestBytes,
  canonicalResponseBytes,
  hexBytes,
  keyIdFor,
  requestDigest,
  verifyS13Message,
  bytesHex,
} from "../src/s13";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..", "..");
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

const hex = (bytes: Uint8Array): string => bytesHex(bytes);

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const serve = (federation: S13DO, path: string, init?: RequestInit): Promise<Response> =>
  federation.fetch(new Request(`https://do.internal${path}`, init));

// A fresh ed25519 keypair with its raw 32-byte public (the trust
// graph's registration form) and its signer — the signer FRAMES in
// the S13-MESSAGE domain exactly as signatif's SignatureSlot::sign
// does (the foreign harness's duty under Annex B.5).
function verifierKey() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const raw = new Uint8Array(der.subarray(12)); // SPKI: 12-byte header, then the point
  return {
    publicHex: hex(raw),
    sign: (payload: Uint8Array): number[] => {
      const tag = new TextEncoder().encode("UNIDPP-SIGNATIF/S13-MESSAGE");
      const framed = new Uint8Array(tag.length + 1 + payload.length);
      framed.set(tag);
      framed[tag.length] = 0;
      framed.set(payload, tag.length + 1);
      return [...nodeCrypto.sign(null, Buffer.from(framed), privateKey)];
    },
  };
}

const toBytes = (numbers: number[]): Uint8Array => new Uint8Array(numbers);

describe("the S13 canonical encoders against the golden fixtures", () => {
  const fixture = (name: string): Record<string, unknown> =>
    JSON.parse(readFileSync(path.join(ROOT, "unidpp-core", "crates", "s13", "fixtures", "canonical", name), "utf8"));

  it("the request's canonical bytes and digest match the fixture", () => {
    const f = fixture("request.json");
    const request = f.request as S13RequestDoc;
    expect(hex(canonicalRequestBytes(request))).toBe(f.canonical_hex);
    expect(digestHex(core, canonicalRequestBytes(request))).toBe(f.digest_hex);
    expect(hex(requestDigest(core, request))).toBe(f.digest_hex);
  });

  it("the response's canonical bytes match the fixture", () => {
    const f = fixture("response.json");
    expect(hex(canonicalResponseBytes(f.response as never))).toBe(f.canonical_hex);
  });

  it("a segment change digests differently (the binding is real)", () => {
    const f = fixture("request.json");
    const request = f.request as S13RequestDoc;
    const other = { ...request, segment: "eu-static" };
    expect(digestHex(core, canonicalRequestBytes(other))).not.toBe(f.digest_hex);
  });
});

describe("the F2 signed-exchange vector", () => {
  const exchange = JSON.parse(
    readFileSync(path.join(ROOT, "unidpp-signatif", "fixtures", "canonical", "s13-signed-exchange.json"), "utf8"),
  ) as {
    requester_public_hex: string;
    responder_public_hex: string;
    signed_request: { request: S13RequestDoc; requester: string; signature: { suite: string; key_id: string; signature: number[] } };
    signed_response: { response: Parameters<typeof canonicalResponseBytes>[0]; signature: { suite: string; key_id: string; signature: number[] } };
  };

  it("the key ids derive from the public keys (Annex B)", () => {
    expect(keyIdFor(core, "ed25519", hexBytes(exchange.requester_public_hex))).toBe(
      exchange.signed_request.signature.key_id,
    );
    expect(keyIdFor(core, "ed25519", hexBytes(exchange.responder_public_hex))).toBe(
      exchange.signed_response.signature.key_id,
    );
  });

  it("the verifier's signed request verifies through the boundary", () => {
    const verified = verifyS13Message(
      core,
      exchange.signed_request.signature.suite,
      hexBytes(exchange.requester_public_hex),
      canonicalRequestBytes(exchange.signed_request.request),
      toBytes(exchange.signed_request.signature.signature!),
    );
    expect(verified).toBe(true);
    // A tampered subject fails the slot.
    const tampered = verifyS13Message(
      core,
      exchange.signed_request.signature.suite,
      hexBytes(exchange.requester_public_hex),
      canonicalRequestBytes({ ...exchange.signed_request.request, subject: "urn:unidpp:passport:other" }),
      toBytes(exchange.signed_request.signature.signature!),
    );
    expect(tampered).toBe(false);
  });

  it("the custodian's signed response verifies through the boundary", () => {
    const verified = verifyS13Message(
      core,
      exchange.signed_response.signature.suite,
      hexBytes(exchange.responder_public_hex),
      canonicalResponseBytes(exchange.signed_response.response),
      toBytes(exchange.signed_response.signature.signature!),
    );
    expect(verified).toBe(true);
  });
});

describe("the federation DO", () => {
  const policy = {
    policy_id: "cn-dynamic-bms",
    version: 1,
    authority: "cn-samr",
    readers: ["cn-customs"],
    verifiers: ["cn-customs", "de-zoll"],
    writers: ["weilian-shenzhen"],
    reveal: "OriginSealed",
    suites: ["sm2"],
    valid_from: "2027-01-01T00:00:00Z",
    valid_to: null,
    superseded_by: null,
  };

  const request = (subject: string): S13RequestDoc => ({
    verifier: "de-zoll",
    subject,
    profile: "urn:unidpp:profile:eu-battery",
    segment: "cn-dynamic",
    at: "2030-06-01T08:00:00Z",
  });

  async function bootstrap(): Promise<{ federation: S13DO; key: ReturnType<typeof verifierKey> }> {
    const federation = new S13DO(storage(), {});
    await serve(federation, "/custodian"); // loads the journal, registers the operators
    const key = verifierKey();
    const node = await serve(federation, "/nodes", {
      method: "POST",
      body: JSON.stringify({ node_id: "de-zoll", suite: "ed25519", public_hex: key.publicHex }),
    });
    expect(node.status).toBe(201);
    await serve(federation, "/policies", { method: "POST", body: JSON.stringify(policy) });
    const pin = await serve(federation, "/segments", {
      method: "POST",
      body: JSON.stringify({ segment: "cn-dynamic", policy_id: "cn-dynamic-bms", version: 1 }),
    });
    expect(pin.status).toBe(201);
    return { federation, key };
  }

  it("the operators self-register under their seeded keys", async () => {
    const federation = new S13DO(storage(), {});
    const custodian = await serve(federation, "/custodian");
    expect(custodian.status).toBe(200);
    const document = (await custodian.json()) as {
      custodian: string;
      key_id: string;
      public_hex: string;
      authority: string;
      authority_key_id: string;
    };
    expect(document.custodian).toBe("unidpp-custodian");
    expect(document.key_id).toMatch(/^k-[0-9a-f]{16}$/);
    expect(document.authority_key_id).toMatch(/^k-[0-9a-f]{16}$/);
    expect(document.key_id).not.toBe(document.authority_key_id);
    const nodes = await serve(federation, "/nodes");
    const listed = (await nodes.json()) as { count: number };
    expect(listed.count).toBe(2);
  });

  it("answers a foreign signed request and the answer verifies", async () => {
    const { federation, key } = await bootstrap();
    const signed = {
      request: request("urn:unidpp:passport:pack-0001"),
      requester: "de-zoll",
      signature: {
        suite: "ed25519",
        key_id: keyIdFor(core, "ed25519", hexBytes(key.publicHex)),
        signature: key.sign(canonicalRequestBytes(request("urn:unidpp:passport:pack-0001"))),
      },
    };
    const answered = await serve(federation, "/requests", {
      method: "POST",
      body: JSON.stringify(signed),
    });
    if (answered.status !== 201) console.log("S13-DEBUG:", await answered.text());
    expect(answered.status).toBe(201);
    const out = (await answered.json()) as {
      request_digest: string;
      signed_response: {
        response: Parameters<typeof canonicalResponseBytes>[0];
        signature: { key_id: string; signature: number[] };
      };
    };
    // The same request fields digest to the golden fixture's digest.
    const golden = JSON.parse(
      readFileSync(path.join(ROOT, "unidpp-core", "crates", "s13", "fixtures", "canonical", "request.json"), "utf8"),
    ) as { digest_hex: string };
    expect(out.request_digest).toBe(golden.digest_hex);
    // The origin-sealed class offers the authority's attestation service.
    expect(out.signed_response.response.outcome.outcome).toBe("attestation-offer");
    expect(out.signed_response.response.outcome.attestation_service).toBe("cn-samr-attestation");
    expect(out.signed_response.response.governing_policy).toBe("cn-dynamic-bms");
    // The answer verifies under the custodian's registered key.
    const custodian = (await (await serve(federation, "/custodian")).json()) as { public_hex: string };
    expect(
      verifyS13Message(
        core,
        "ed25519",
        hexBytes(custodian.public_hex),
        canonicalResponseBytes(out.signed_response.response),
        toBytes(out.signed_response.signature.signature!),
      ),
    ).toBe(true);
  });

  it("the journal replays: every entry verifies, the decision is the outcome", async () => {
    const { federation, key } = await bootstrap();
    const signed = {
      request: request("urn:unidpp:passport:pack-0001"),
      requester: "de-zoll",
      signature: {
        suite: "ed25519",
        key_id: keyIdFor(core, "ed25519", hexBytes(key.publicHex)),
        signature: key.sign(canonicalRequestBytes(request("urn:unidpp:passport:pack-0001"))),
      },
    };
    const answered = await serve(federation, "/requests", { method: "POST", body: JSON.stringify(signed) });
    expect(answered.status).toBe(201);
    const journal = await serve(federation, "/journal");
    expect(journal.status).toBe(200);
    const replayed = (await journal.json()) as {
      side: string;
      count: number;
      entries: unknown[];
      decisions: { outcome: string; governing_policy: string }[];
    };
    expect(replayed.side).toBe("custodian");
    expect(replayed.count).toBe(2);
    expect(replayed.decisions).toHaveLength(1);
    expect(replayed.decisions[0]!.outcome).toBe("attestation-offer");
    expect(replayed.decisions[0]!.governing_policy).toBe("cn-dynamic-bms");
  });

  it("the authority counter-signs at the exact monotone place", async () => {
    const { federation, key } = await bootstrap();
    const ask = async (subject: string) => {
      const signed = {
        request: request(subject),
        requester: "de-zoll",
        signature: {
          suite: "ed25519",
          key_id: keyIdFor(core, "ed25519", hexBytes(key.publicHex)),
          signature: key.sign(canonicalRequestBytes(request(subject))),
        },
      };
      const answered = (await (await serve(federation, "/requests", {
        method: "POST",
        body: JSON.stringify(signed),
      })).json()) as { request_digest: string };
      return answered.request_digest;
    };
    const first = await ask("urn:unidpp:passport:pack-0001");
    const second = await ask("urn:unidpp:passport:pack-0002");
    const cs1 = await serve(federation, "/countersign", {
      method: "POST",
      body: JSON.stringify({ request_digest: second }),
    });
    expect(cs1.status).toBe(201);
    const nr1 = (await cs1.json()) as {
      sequence: number;
      authority: string;
      authority_signature: { signature: number[] };
      signed: { response: Parameters<typeof authorityPayloadBytes>[0] };
    };
    expect(nr1.sequence).toBe(1);
    expect(nr1.authority).toBe("unidpp-authority");
    const authority = (await (await serve(federation, "/custodian")).json()) as { authority_public_hex: string };
    expect(
      verifyS13Message(
        core,
        "ed25519",
        hexBytes(authority.authority_public_hex),
        authorityPayloadBytes(nr1.signed.response, nr1.sequence),
        toBytes(nr1.authority_signature.signature!),
      ),
    ).toBe(true);
    // A second answer for the SAME subject countersigns at the next
    // place (the sequence is per (subject, custodian), from 1).
    const third = await ask("urn:unidpp:passport:pack-0002");
    const cs2 = await serve(federation, "/countersign", {
      method: "POST",
      body: JSON.stringify({ request_digest: third }),
    });
    expect(cs2.status).toBe(201);
    const nr2 = (await cs2.json()) as { sequence: number };
    expect(nr2.sequence).toBe(2);
    // A digest no journaled answer carries refuses.
    const absent = await serve(federation, "/countersign", {
      method: "POST",
      body: JSON.stringify({ request_digest: "ab".repeat(32) }),
    });
    expect(absent.status).toBe(404);
    // The journal replays with every decision in sequence (three
    // answers journaled, two of them counter-signed).
    const replayed = (await (await serve(federation, "/journal")).json()) as {
      decisions: unknown[];
    };
    expect(replayed.decisions).toHaveLength(5);
  });

  it("refuses an unregistered verifier and a forged signature", async () => {
    const { federation, key } = await bootstrap();
    // An unknown node: refused before any evaluation.
    const stranger = {
      request: request("urn:unidpp:passport:pack-0001"),
      requester: "jp-meti",
      signature: { suite: "ed25519", key_id: "k-0000000000000000", signature: key.sign(canonicalRequestBytes(request("urn:unidpp:passport:pack-0001"))) },
    };
    expect(
      (await serve(federation, "/requests", { method: "POST", body: JSON.stringify(stranger) })).status,
    ).toBe(403);
    // A registered node whose signature does not cover these bytes.
    const forged = {
      request: request("urn:unidpp:passport:tampered"),
      requester: "de-zoll",
      signature: {
        suite: "ed25519",
        key_id: keyIdFor(core, "ed25519", hexBytes(key.publicHex)),
        signature: key.sign(canonicalRequestBytes(request("urn:unidpp:passport:pack-0001"))),
      },
    };
    expect(
      (await serve(federation, "/requests", { method: "POST", body: JSON.stringify(forged) })).status,
    ).toBe(403);
  });

  it("a segment without a governing policy answers a stated denial", async () => {
    const { federation, key } = await bootstrap();
    const unpinned: S13RequestDoc = { ...request("urn:unidpp:passport:pack-0003"), segment: "eu-static" };
    const signed = {
      request: unpinned,
      requester: "de-zoll",
      signature: {
        suite: "ed25519",
        key_id: keyIdFor(core, "ed25519", hexBytes(key.publicHex)),
        signature: key.sign(canonicalRequestBytes(unpinned)),
      },
    };
    const answered = (await (await serve(federation, "/requests", {
      method: "POST",
      body: JSON.stringify(signed),
    })).json()) as { signed_response: { response: { outcome: { outcome: string; reason?: string }; governing_policy: string } } };
    expect(answered.signed_response.response.outcome.outcome).toBe("deny");
    expect(answered.signed_response.response.outcome.reason).toContain("eu-static");
    expect(answered.signed_response.response.governing_policy).toBe("");
  });
});
