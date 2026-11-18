import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";

const inst = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync("src/core_bg.wasm")),
  {},
);
useWorkerCore(inst.exports as never);

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const REQUEST = {
  type: "custody.transfer",
  data: { from: "urn:eo:maker", to: "urn:eo:holder", counterparty_signed: true },
  at: "2026-01-15T08:30:00Z",
  actor: "urn:eo:maker",
};

// The gate runs when the native one-binary is reachable on the dev
// port (the harness and the parity rounds' environment); offline the
// cross-check skips loudly, never silently.
const nativeUp = await fetch("http://127.0.0.1:8091/healthz")
  .then((r) => r.ok)
  .catch(() => false);

describe("the native cross-check", () => {
  (nativeUp ? it : it.skip)(
    "seals the same event document and signature as the native intake",
    async () => {
    // The native one-binary (default dev keys) and the DO (the same
    // dev label derivation) run the identical intake.
    const mintBody = JSON.stringify({ identity: "local:cross:seal" });
    const nativeMint = await fetch("http://127.0.0.1:8091/issuer/passports", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: mintBody,
    });
    expect(nativeMint.status).toBe(201);
    const nativeId = ((await nativeMint.json()) as { passport_id: string }).passport_id;

    const issuer = new IssuerDO(storage());
    const serve = (p: string, init?: RequestInit) =>
      issuer.fetch(new Request(`https://do.internal${p}`, init));
    const edgeMint = await serve("/passports", {
      method: "POST",
      body: JSON.stringify({ identity: "local:cross:seal" }),
    });
    expect(edgeMint.status).toBe(201);
    const edgeId = ((await edgeMint.json()) as { passport_id: string }).passport_id;

    const post = (url: string) =>
      fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(REQUEST),
      });
    const nativeRes = await post(
      `http://127.0.0.1:8091/issuer/passports/${encodeURIComponent(nativeId)}/events`,
    );
    expect(nativeRes.status).toBe(201);
    const edgeRes = await serve(`/passports/${encodeURIComponent(edgeId)}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(REQUEST),
    });
    expect(edgeRes.status).toBe(201);

    const nativeDoc = (await (
      await fetch(`http://127.0.0.1:8091/issuer/passports/${encodeURIComponent(nativeId)}`)
    ).json()) as { log: { sealed: { event: unknown }[] }; event_signatures: unknown[] };
    const edgeDoc = (await (
      await serve(`/passports/${encodeURIComponent(edgeId)}`)
    ).json()) as { log: { sealed: { event: unknown }[] }; event_signatures: unknown[] };
    const nativeEvent = nativeDoc.log.sealed[nativeDoc.log.sealed.length - 1].event;
    const edgeEvent = edgeDoc.log.sealed[edgeDoc.log.sealed.length - 1].event;
    expect(JSON.stringify(edgeEvent)).toBe(JSON.stringify(nativeEvent));
    const nativeSig = nativeDoc.event_signatures[nativeDoc.event_signatures.length - 1];
    const edgeSig = edgeDoc.event_signatures[edgeDoc.event_signatures.length - 1];
    expect(JSON.stringify(edgeSig)).toBe(JSON.stringify(nativeSig));
  });
});
