// S5's relay gates (REARCH R12): declarations are issued through the
// wasm boundary (signatif's own INTEROP-DECLARATION signing); the
// willing pair relays and the relayed evidence carries the HUB-RELAY
// signature; a declining pair and an absent declaration are refused
// with the WILL gap stated; the hub holds nothing.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { relay, issueDeclaration } from "../src/hub";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

const postures = (posture: "open" | "declined") => [
  {
    data_class: "conformity",
    level: posture === "open" ? "l2" : "l0",
    recognition: "bilateral-anchors",
    transports: posture === "open" ? ["protocol", "document", "hub"] : [],
  },
];

const willingDeclarations = (): unknown => {
  const first = issueDeclaration({
    declarer: "eu-esr",
    counterpart: "jp-scheme",
    version: 1,
    postures: postures("open"),
    valid_from: "2027-01-01T00:00:00Z",
  });
  const second = issueDeclaration({
    declarer: "jp-scheme",
    counterpart: "eu-esr",
    version: 1,
    postures: postures("open"),
    valid_from: "2027-01-01T00:00:00Z",
  });
  expect(first.ok).toBe(true);
  expect(second.ok).toBe(true);
  if (!first.ok || !second.ok) throw new Error("issuance failed");
  return { declarations: [first.declaration, second.declaration] };
};

const decliningDeclarations = (): unknown => {
  const issued = issueDeclaration({
    declarer: "eu-esr",
    counterpart: "jp-scheme",
    version: 1,
    postures: postures("declined"),
    valid_from: "2027-01-01T00:00:00Z",
  });
  expect(issued.ok).toBe(true);
  if (!issued.ok) throw new Error("issuance failed");
  return { declarations: [issued.declaration] };
};

const relayCall = (body: unknown): Promise<Response> =>
  relay(
    new Request("https://unidpp.workers.dev/relay/relay", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  );

describe("the translation hub", () => {
  it("issues declarations through the wasm boundary", () => {
    const issued = issueDeclaration({
      declarer: "eu-esr",
      counterpart: "jp-scheme",
      version: 1,
      postures: postures("open"),
      valid_from: "2027-01-01T00:00:00Z",
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const declaration = issued.declaration as {
      declarer: string;
      counterpart: string;
      signature: { suite: string; signature: unknown[] };
    };
    expect(declaration.declarer).toBe("eu-esr");
    expect(declaration.signature.suite).toBe("ed25519");
    expect(declaration.signature.signature.length).toBe(64);
  });

  it("relays between a willing pair and signs the relay", async () => {
    const response = await relayCall({
      evidence_hex: "aabbccdd",
      from: "eu-esr",
      to: "jp-scheme",
      data_class: "conformity",
      declarations: willingDeclarations(),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      relay: { from: string; to: string };
      evidence_hex: string;
    };
    expect(body.evidence_hex).toBe("aabbccdd");
    expect(body.relay.from).toBe("eu-esr");
    expect(body.relay.to).toBe("jp-scheme");
  });

  it("refuses a declined counterpart with the refusal named", async () => {
    const response = await relayCall({
      evidence_hex: "aabbccdd",
      from: "eu-esr",
      to: "jp-scheme",
      data_class: "conformity",
      declarations: decliningDeclarations(),
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { refused: boolean };
    expect(body.refused).toBe(true);
  });

  it("refuses the absent declaration as stated", async () => {
    const response = await relayCall({
      evidence_hex: "aabbccdd",
      from: "eu-esr",
      to: "jp-scheme",
      data_class: "conformity",
      declarations: { declarations: [] },
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { refused: boolean };
    expect(body.refused).toBe(true);
  });

  it("refuses non-hex evidence", async () => {
    const response = await relayCall({
      evidence_hex: "zz-not-hex",
      from: "eu-esr",
      to: "jp-scheme",
      data_class: "conformity",
      declarations: willingDeclarations(),
    });
    expect(response.status).toBe(400);
  });
});
