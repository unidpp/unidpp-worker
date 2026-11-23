// The parity routes of the render module and the hub (REARCH R12
// S5-serve, mirrored against the native one-binary): the discovery
// documents at the module roots, the consumer report channel
// (journaled, sequenced, receipted; the public citation withholds
// the contact; the admin listing answers to the operator token), the
// scan-token gate (off unless a policy is configured), the hub's
// keyring and its relay verification (both the native
// /relay/verify form and the estate's doubled forward), with the
// native refusal texts stated exactly.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { discovery as renderDiscovery, render } from "../src/render";
import { discovery as hubDiscovery, keyring, relay, issueDeclaration } from "../src/hub";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

// The estate passes render() the prefix-stripped pathname (the query
// rides the Request); the helpers split the same way.
const post = (path: string, body?: string, env?: Record<string, string>): Promise<Response> =>
  render(
    path.split("?")[0],
    new Request(`https://app.unidpp.org/render${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    }),
    env ?? {},
  );

const get = (path: string, env?: Record<string, string>): Promise<Response> =>
  render(path.split("?")[0], new Request(`https://app.unidpp.org/render${path}`), env ?? {});

describe("the render module root", () => {
  it("serves the discovery document the native gateway serves", async () => {
    const served = await renderDiscovery(new Request("https://app.unidpp.org/render"), {});
    expect(served.status).toBe(200);
    expect(served.headers.get("x-as-of")).toBeTruthy();
    const doc = (await served.json()) as {
      service?: string;
      as_of?: string;
      build_id?: string;
      version?: string;
      bindings?: Record<string, { profile?: string; endpoint?: string }>;
      endpoints?: Record<string, string>;
      conventions?: string[];
      c4?: string;
      source?: { mode?: string; fixtures?: { passport_id?: string; product_id?: string; gtin?: string }[] };
    };
    expect(doc.service).toBe("unidpp-gateway");
    expect(doc.as_of).toBeTruthy();
    expect(doc.build_id).toBe("dev");
    expect(doc.version).toBe("0.1.0");
    expect(doc.bindings?.en18222?.profile).toBe("urn:unidpp:profile:render:en18222");
    expect(doc.bindings?.untp?.profile).toBe("urn:unidpp:profile:render:untp");
    expect(doc.endpoints?.feedback).toContain("POST /feedback");
    expect(doc.endpoints?.feedback_citation).toContain("GET /feedback/{seq}");
    expect(doc.endpoints?.feedback_admin).toContain("GET /admin/feedback");
    expect(doc.endpoints?.scan_tokens).toContain("POST /scan-tokens");
    expect(doc.conventions?.length).toBe(3);
    expect(doc.c4).toContain("C4 protocol renderings");
    // The source posture: the estate's issuer upstream with the
    // built-in fixture fallback, and the fixture index names the
    // demo passport (the native fixture_index's shape).
    expect(doc.source?.mode).toBe("issuer-upstream-with-fixture-fallback");
    expect(doc.source?.fixtures?.[0]?.passport_id).toBe(
      "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345",
    );
    expect(doc.source?.fixtures?.[0]?.product_id).toBeTruthy();
  });
});

describe("the consumer report channel", () => {
  const first = JSON.stringify({
    identifier: "gs1:(01)06901234567892",
    category: "goods-mismatch",
    contact: "reporter@example.org",
    details: "the package says 20 Ah, the page says 0.072 kWh",
  });

  it("receipts a filed report with the contact withheld", async () => {
    const served = await post("/feedback", first);
    expect(served.status).toBe(201);
    // The receipt is a wire-shaped answer: no as-of stamp.
    expect(served.headers.get("x-as-of")).toBeNull();
    const receipt = (await served.json()) as {
      seq?: number;
      recorded_at?: string;
      identifier?: string;
      category?: string;
      contact?: string;
      details?: string;
    };
    expect(receipt.seq).toBeGreaterThan(0);
    expect(receipt.recorded_at).toBeTruthy();
    expect(receipt.identifier).toBe("gs1:(01)06901234567892");
    expect(receipt.category).toBe("goods-mismatch");
    // The omission is stated, never silent.
    expect(receipt.contact).toBe("withheld");
    expect(receipt.details).toContain("20 Ah");
  });

  it("files an unstated category as the free-form other", async () => {
    const served = await post(
      "/feedback",
      JSON.stringify({ identifier: "cpid:x", category: "other:packaging", details: "the box was damaged" }),
    );
    expect(served.status).toBe(201);
    const receipt = (await served.json()) as { category?: string; contact?: string };
    expect(receipt.category).toBe("other:other:packaging");
    expect(receipt.contact).toBe("withheld");
  });

  it("refuses the unstated with the native texts", async () => {
    const noIdentifier = await post("/feedback", "{}");
    expect(noIdentifier.status).toBe(400);
    expect(noIdentifier.headers.get("x-as-of")).toBeTruthy();
    const body = (await noIdentifier.json()) as { error?: string; as_of?: string };
    expect(body.error).toBe("`identifier` is required — a report is about something");
    expect(body.as_of).toBeTruthy();
    const noDetails = await post("/feedback", JSON.stringify({ identifier: "x" }));
    expect(noDetails.status).toBe(400);
    expect(((await noDetails.json()) as { error?: string }).error).toBe(
      "`details` is required — a report states what did not match",
    );
    const tooLong = await post(
      "/feedback",
      JSON.stringify({ identifier: "x", details: "a".repeat(501) }),
    );
    expect(tooLong.status).toBe(400);
    expect(((await tooLong.json()) as { error?: string }).error).toBe(
      "`details` exceeds 500 characters",
    );
    const malformed = await post("/feedback", "nope");
    expect(malformed.status).toBe(400);
    expect(((await malformed.json()) as { error?: string }).error).toBe(
      "invalid JSON body: expected ident at line 1 column 2",
    );
  });

  it("cites a filed report by sequence", async () => {
    const listing = (await (await get("/admin/feedback")).json()) as { records?: { seq: number }[] };
    const seq = listing.records?.[0]?.seq ?? 1;
    const served = await get(`/feedback/${seq}`);
    expect(served.status).toBe(200);
    // The citation is a wire-shaped answer: no as-of stamp.
    expect(served.headers.get("x-as-of")).toBeNull();
    const citation = (await served.json()) as { seq?: number; contact?: string };
    expect(citation.seq).toBe(seq);
    expect(citation.contact).toBe("withheld");
  });

  it("states the no-information 404 and the path rejection", async () => {
    const missing = await get("/feedback/999999");
    expect(missing.status).toBe(404);
    expect(missing.headers.get("x-as-of")).toBeTruthy();
    await expect(missing.text()).resolves.toBe('{"error":"not found"}');
    const unparseable = await get("/feedback/abc");
    expect(unparseable.status).toBe(400);
    expect(unparseable.headers.get("content-type")).toContain("text/plain");
    await expect(unparseable.text()).resolves.toBe("Invalid URL: Cannot parse `abc` to a `u64`");
  });

  it("answers the wrong methods with the native 405s", async () => {
    const wrongOnFeedback = await get("/feedback");
    expect(wrongOnFeedback.status).toBe(405);
    expect(wrongOnFeedback.headers.get("allow")).toBe("POST");
    await expect(wrongOnFeedback.text()).resolves.toBe("");
    const wrongOnCitation = await post("/feedback/1");
    expect(wrongOnCitation.status).toBe(405);
    expect(wrongOnCitation.headers.get("allow")).toBe("GET,HEAD");
    const wrongOnScan = await get("/scan-tokens");
    expect(wrongOnScan.status).toBe(405);
    expect(wrongOnScan.headers.get("allow")).toBe("POST");
  });

  it("lists the reports for the operator, newest first", async () => {
    const served = await get("/admin/feedback");
    expect(served.status).toBe(200);
    expect(served.headers.get("x-as-of")).toBeNull();
    const listing = (await served.json()) as {
      offset?: number;
      total?: number;
      records?: { seq: number; contact?: string | null }[];
    };
    expect(listing.offset).toBe(0);
    expect(listing.total).toBeGreaterThanOrEqual(2);
    expect(listing.records?.length).toBe(listing.total);
    // Newest first, contacts included (null stated for the absent).
    const seqs = (listing.records ?? []).map((r) => r.seq);
    for (let i = 1; i < seqs.length; i++) {
      expect(seqs[i]).toBeLessThan(seqs[i - 1]);
    }
    expect(seqs[0]).toBe(Math.max(...seqs));
    const withContact = (listing.records ?? []).filter((r) => typeof r.contact === "string");
    expect(withContact.length).toBeGreaterThanOrEqual(1);
    expect((listing.records ?? []).some((r) => r.contact === null)).toBe(true);
    // The window echoes limit and offset.
    const windowed = (await (await get("/admin/feedback?limit=1&offset=1")).json()) as {
      records?: unknown[];
      total?: number;
    };
    expect(windowed.records?.length).toBe(1);
    expect(windowed.total).toBe(listing.total);
  });

  it("gates the listing on the operator token when configured", async () => {
    const guarded = { UNIDPP_GATEWAY_ADMIN_TOKEN: "op-secret" };
    const denied = await get("/admin/feedback", guarded);
    expect(denied.status).toBe(401);
    expect(((await denied.json()) as { error?: string }).error).toBe("unauthorized");
    const admitted = await render(
      "/admin/feedback",
      new Request("https://app.unidpp.org/render/admin/feedback", {
        headers: { authorization: "Bearer op-secret" },
      }),
      guarded,
    );
    expect(admitted.status).toBe(200);
  });
});

describe("the scan-token gate", () => {
  it("states the open gate when no policy is configured", async () => {
    const served = await post("/scan-tokens", JSON.stringify({ source: "mobileqr" }));
    expect(served.status).toBe(409);
    const body = (await served.json()) as { error?: string; gate?: string };
    expect(body.error).toBe("no scan policy is configured — the gate is open, no token needed");
    expect(body.gate).toBe("open");
  });

  it("issues under the policy and states the throttle", async () => {
    const policy = { UNIDPP_GATEWAY_SCAN_TTL_SECS: "60", UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN: "1" };
    const served = await post("/scan-tokens", JSON.stringify({ source: "qa-rig" }), policy);
    expect(served.status).toBe(201);
    const issued = (await served.json()) as { source?: string; token?: string; ttl_secs?: number };
    expect(issued.source).toBe("qa-rig");
    expect(issued.token).toMatch(/^scan-[0-9a-f]{16}$/);
    expect(issued.ttl_secs).toBe(60);
    const throttled = await post("/scan-tokens", JSON.stringify({ source: "qa-rig" }), policy);
    expect(throttled.status).toBe(429);
    expect(((await throttled.json()) as { error?: string }).error).toBe(
      "scan-token issuance limit: at most 1 per source per minute — refused, retry after the window",
    );
    // A different source carries its own window.
    const other = await post("/scan-tokens", JSON.stringify({ source: "other-rig" }), policy);
    expect(other.status).toBe(201);
  });

  it("guards the render routes once a policy is on", async () => {
    const policy = { UNIDPP_GATEWAY_SCAN_TTL_SECS: "60" };
    const index = (await (
      await renderDiscovery(new Request("https://app.unidpp.org/render"), {})
    ).json()) as { source?: { fixtures?: { passport_id?: string }[] } };
    const fixtureId = index.source?.fixtures?.[0]?.passport_id ?? "";
    const bare = await get(`/untp/product/${fixtureId}`, policy);
    expect(bare.status).toBe(401);
    expect(((await bare.json()) as { error?: string }).error).toBe(
      "scan token required: this gateway enforces a 60 s scan policy — obtain one from POST /scan-tokens",
    );
    const unknown = await render(
      `/untp/product/${fixtureId}`,
      new Request(`https://app.unidpp.org/render/untp/product/${fixtureId}`, {
        headers: { "x-unidpp-scan": "scan-nope" },
      }),
      policy,
    );
    expect(unknown.status).toBe(401);
    expect(((await unknown.json()) as { error?: string }).error).toBe("unknown scan token");
    // A live token admits the render.
    const issued = await post("/scan-tokens", JSON.stringify({ source: "admit-rig" }), policy);
    const { token } = (await issued.json()) as { token: string };
    const admitted = await render(
      `/untp/product/${fixtureId}`,
      new Request(`https://app.unidpp.org/render/untp/product/${fixtureId}`, {
        headers: { "x-unidpp-scan": token },
      }),
      policy,
    );
    expect(admitted.status).toBe(200);
  });
});

describe("the hub's discovery and keyring", () => {
  it("serves the discovery document at the module root", async () => {
    const served = hubDiscovery(new Request("https://app.unidpp.org/relay"));
    expect(served.status).toBe(200);
    expect(served.headers.get("x-as-of")).toBeTruthy();
    const doc = (await served.json()) as {
      service?: string;
      hub_id?: string;
      contract?: string[];
      endpoints?: Record<string, string>;
      description?: string;
    };
    expect(doc.service).toBe("unidpp-hub");
    expect(doc.hub_id).toBe("unidpp-hub-1");
    expect(doc.contract?.length).toBe(4);
    expect(doc.endpoints?.relay_verify).toContain("POST /relay/verify");
    expect(doc.endpoints?.keyring).toContain("GET /keyring");
  });

  it("serves the relay role's public anchor", async () => {
    const served = keyring(new Request("https://app.unidpp.org/relay/keyring"));
    expect(served.status).toBe(200);
    const body = (await served.json()) as {
      mode?: string;
      roles?: { relay?: { public_hex?: string; suite?: string } };
    };
    expect(body.mode).toBe("seeded-dev");
    expect(body.roles?.relay?.suite).toBe("ed25519");
    expect(body.roles?.relay?.public_hex).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("the relay verification", () => {
  const willingDeclarations = (): unknown => {
    const postures = [
      {
        data_class: "conformity",
        level: "l2",
        recognition: "bilateral-anchors",
        transports: ["protocol", "document", "hub"],
      },
    ];
    const first = issueDeclaration({
      declarer: "eu-esr",
      counterpart: "jp-scheme",
      version: 1,
      postures,
      valid_from: "2027-01-01T00:00:00Z",
    });
    const second = issueDeclaration({
      declarer: "jp-scheme",
      counterpart: "eu-esr",
      version: 1,
      postures,
      valid_from: "2027-01-01T00:00:00Z",
    });
    if (!first.ok || !second.ok) throw new Error("issuance failed");
    return { declarations: [first.declaration, second.declaration] };
  };

  const relayOnce = async (): Promise<{ envelope: Record<string, unknown>; evidence: string }> => {
    const response = await relay(
      new Request("https://app.unidpp.org/relay/relay", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          evidence_hex: "aabbccdd",
          from: "eu-esr",
          to: "jp-scheme",
          data_class: "conformity",
          declarations: willingDeclarations(),
        }),
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { relay: Record<string, unknown>; evidence_hex: string };
    return { envelope: body.relay, evidence: body.evidence_hex };
  };

  const verifyCall = (body: string, path = "/relay/relay/verify"): Promise<Response> =>
    relay(
      new Request(`https://app.unidpp.org${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      }),
    );

  it("verifies the relay it signed", async () => {
    const { envelope, evidence } = await relayOnce();
    const served = await verifyCall(JSON.stringify({ evidence_hex: evidence, relay: envelope }));
    expect(served.status).toBe(200);
    const verdict = (await served.json()) as { verified?: boolean; evidence_digest?: string };
    expect(verdict.verified).toBe(true);
    expect(verdict.evidence_digest).toMatch(/^[0-9a-f]{64}$/);
    // The doubled form the estate forwards and the bare native form
    // answer identically.
    const bare = await verifyCall(
      JSON.stringify({ evidence_hex: evidence, relay: envelope }),
      "/relay/verify",
    );
    expect(bare.status).toBe(200);
    expect(((await bare.json()) as { verified?: boolean }).verified).toBe(true);
  });

  it("refuses a tampered relay with the native verdict", async () => {
    const { envelope, evidence } = await relayOnce();
    const tampered = {
      ...(envelope as { signature: { signature: number[] } }),
      signature: {
        ...(envelope as { signature: { signature: number[] } }).signature,
        signature: (envelope as { signature: { signature: number[] } }).signature.signature.map(
          (b: number, i: number) => (i === 0 ? b ^ 0xff : b),
        ),
      },
    };
    const served = await verifyCall(JSON.stringify({ evidence_hex: evidence, relay: tampered }));
    expect(served.status).toBe(200);
    const verdict = (await served.json()) as { verified?: boolean; error?: string };
    expect(verdict.verified).toBe(false);
    expect(verdict.error).toBe("cryptographic error: Ed25519 signature invalid");
    // The bytes not matching the attested digest refuse the same way
    // (the payload covers the forwarded bytes' digest).
    const wrongBytes = await verifyCall(
      JSON.stringify({ evidence_hex: "11223344", relay: envelope }),
    );
    expect(((await wrongBytes.json()) as { verified?: boolean }).verified).toBe(false);
  });

  it("answers the native deserialization rejections exactly", async () => {
    const empty = await verifyCall("{}");
    expect(empty.status).toBe(422);
    expect(empty.headers.get("content-type")).toContain("text/plain");
    await expect(empty.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: missing field `evidence_hex` at line 1 column 2",
    );
    const noRelay = await verifyCall('{"evidence_hex":"aa"}');
    expect(noRelay.status).toBe(422);
    await expect(noRelay.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: missing field `relay` at line 1 column 21",
    );
    const wrongType = await verifyCall('{"evidence_hex":123,"relay":{}}');
    expect(wrongType.status).toBe(422);
    await expect(wrongType.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: evidence_hex: invalid type: integer `123`, expected a string at line 1 column 19",
    );
    const nestedMissing = await verifyCall('{"evidence_hex":"aa","relay":{"from":"a"}}');
    expect(nestedMissing.status).toBe(422);
    await expect(nestedMissing.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: relay: missing field `hub_id` at line 1 column 41",
    );
    const malformed = await verifyCall("nope");
    expect(malformed.status).toBe(400);
    await expect(malformed.text()).resolves.toBe(
      "Failed to parse the request body as JSON: expected ident at line 1 column 2",
    );
  });

  it("refuses non-hex evidence with the native text", async () => {
    const { envelope } = await relayOnce();
    const served = await verifyCall(
      JSON.stringify({ evidence_hex: "zz", relay: envelope }),
    );
    expect(served.status).toBe(400);
    expect(((await served.json()) as { error?: string }).error).toBe("`evidence_hex`: not hex");
    const odd = await verifyCall(
      JSON.stringify({ evidence_hex: "aab", relay: envelope }),
    );
    expect(odd.status).toBe(400);
    expect(((await odd.json()) as { error?: string }).error).toBe(
      "`evidence_hex`: not hex (odd length)",
    );
  });

  it("answers the relay's wrong-typed fields with the native rejection", async () => {
    const served = await relay(
      new Request("https://app.unidpp.org/relay/relay", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: '{"from":5,"to":"b","data_class":"c","evidence_hex":"aa","declarations":[]}',
      }),
    );
    expect(served.status).toBe(422);
    await expect(served.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: from: invalid type: integer `5`, expected a string at line 1 column 9",
    );
    const missing = await relay(
      new Request("https://app.unidpp.org/relay/relay", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: '{"to":"b","data_class":"c","evidence_hex":"aa","declarations":[]}',
      }),
    );
    expect(missing.status).toBe(422);
    await expect(missing.text()).resolves.toBe(
      "Failed to deserialize the JSON body into the target type: missing field `from` at line 1 column 65",
    );
  });

  it("answers the wrong methods with the native 405", async () => {
    for (const path of ["/relay/relay", "/relay/relay/verify"]) {
      const served = await relay(new Request(`https://app.unidpp.org${path}`));
      expect(served.status).toBe(405);
      expect(served.headers.get("allow")).toBe("POST");
      await expect(served.text()).resolves.toBe("");
    }
  });
});

// ---------------------------------------------------------------------------
// The import direction (POST /untp/ingest): the boundary's unidpp_ingest
// export wraps the native gateway's ingest.rs included by path; the
// store is module state. Parity: the deterministic id, the identity,
// the granularity, the profile bindings and the receipt's commitment
// agree with the native one-binary on the same body (the cross-check
// values pinned below were produced by the native ingest route).
// ---------------------------------------------------------------------------

describe("the import direction", () => {
  const triad = (): string =>
    JSON.stringify({
      passport: {
        "@context": "https://www.w3.org/ns/credentials/v2",
        type: "DigitalProductPassport",
        id: "https://render.test/passport/roundtrip",
        productIdentifiers: [
          { scheme: "https://gs1.org/voc/", value: "04012345123456" },
        ],
        passportIssuer: { id: "urn:eo:render-test" },
        validFrom: "2026-01-01T00:00:00Z",
      },
      conformity: [
        {
          credentialSubject: {
            conformity: {
              standard: "urn:unidpp:profile:eu-espr-electronics",
              version: "1.0",
            },
          },
          validFrom: "2026-02-01T00:00:00Z",
        },
      ],
      link: { target: "https://resolve.unidpp.org/r/roundtrip" },
    });

  it("imports a UNTP triad with the deterministic identity and matches on re-import", async () => {
    const first = await post("/untp/ingest", triad());
    expect(first.status).toBe(201);
    const imported = (await first.json()) as {
      status?: string;
      passport_id?: string;
      identity?: string;
      granularity?: string;
      profiles?: { id?: string; version?: string; effective_from?: string }[];
      receipt?: { commitment?: string; source?: { regime?: string } };
    };
    // The native one-binary's own answer for this body (cross-checked).
    expect(imported.passport_id).toBe("urn:unidpp:passport:untp-13615cabb407");
    expect(imported.status).toBe("imported");
    expect(imported.identity).toBe("01+04012345123456");
    expect(imported.granularity).toBe("model");
    expect(imported.profiles?.[0]?.id).toBe("urn:unidpp:profile:eu-espr-electronics");
    expect(imported.profiles?.[0]?.effective_from).toBe("2026-02-01T00:00:00Z");
    expect(imported.receipt?.source?.regime).toBe("untp");
    expect(imported.receipt?.commitment).toMatch(/^[0-9a-f]{64}$/);

    const second = await post("/untp/ingest", triad());
    expect(second.status).toBe(200);
    const matched = (await second.json()) as { status?: string; passport_id?: string };
    expect(matched.status).toBe("matched");
    expect(matched.passport_id).toBe(imported.passport_id);

    // The ingested passport resolves on the render direction (after
    // the issuer and the fixture, the native resolution order).
    const rendered = await get(`/untp/product/${encodeURIComponent(imported.passport_id ?? "")}`);
    expect(rendered.status).toBe(200);
    const body = (await rendered.json()) as { rendering?: { source?: string } };
    expect(body.rendering?.source).toBe("fixture");
    expect(JSON.stringify(body)).toContain("04012345123456");
  });

  it("degrades explicitly on an unmapped scheme and a body with no passport VC", async () => {
    const unmapped = await post(
      "/untp/ingest",
      JSON.stringify({
        passport: {
          productIdentifiers: [
            { scheme: "https://example.org/unknown/", value: "X" },
          ],
        },
      }),
    );
    expect(unmapped.status).toBe(422);
    const degraded = (await unmapped.json()) as { status?: string; reason?: string };
    expect(degraded.status).toBe("degraded");
    expect(degraded.reason).toContain("no C8 mapping");
    expect(degraded.reason).toContain("nothing is minted under a guessed scheme");

    const noVc = await post("/untp/ingest", '{"x":1}');
    expect(noVc.status).toBe(422);
    expect(((await noVc.json()) as { reason?: string }).reason).toContain(
      "no UNTP passport VC found",
    );
  });

  it("answers the wrong method with the native 405", async () => {
    const served = await get("/untp/ingest");
    expect(served.status).toBe(405);
    expect(served.headers.get("allow")).toBe("POST");
    await expect(served.text()).resolves.toBe("");
  });

  it("answers the render routes' wrong methods with the native 405", async () => {
    for (const path of ["/untp/product/x", "/en18222/v1/dppsByProductId/04012345123456"]) {
      const served = await post(path, "{}");
      expect(served.status).toBe(405);
      expect(served.headers.get("allow")).toBe("GET,HEAD");
      await expect(served.text()).resolves.toBe("");
    }
  });
});
