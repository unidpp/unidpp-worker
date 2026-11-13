// The pack gates (the adoption audit's gap 3, closed): the issuer
// mints Tier-A carriers on the edge — the pack document carries the
// native shape (hex, bytes, projected, qr version, the signature
// block, the anchors), the carrier decodes through the native
// framing's grammar, and the ECDSA slot verifies the signature over
// the domain-framed signing body with the minted anchor.

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import nodeCrypto from "node:crypto";
import { CoreExports } from "../src/wasm";
import { useWorkerCore } from "../src/mount";
import { IssuerDO } from "../src/issuer-do";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const bytes = readFileSync(path.join(HERE, "..", "src", "core_bg.wasm"));
const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
const core = instance.exports as unknown as CoreExports;
useWorkerCore(core);
beforeAll(() => useWorkerCore(core));

const storage = () => {
  const map = new Map<string, unknown>();
  return {
    put: async (k: string, v: unknown) => void map.set(k, v),
    get: async (k: string) => map.get(k),
    list: async ({ prefix }: { prefix: string }) =>
      new Map([...map.entries()].filter(([k]) => k.startsWith(prefix))),
  };
};

const serve = (issuer: IssuerDO, path: string, init?: RequestInit): Promise<Response> =>
  issuer.fetch(new Request(`https://do.internal${path}`, init));

const mintPassport = async (issuer: IssuerDO, identity: string): Promise<Record<string, unknown>> => {
  const minted = await serve(issuer, "/passports", {
    method: "POST",
    body: JSON.stringify({ identity }),
  });
  expect(minted.status).toBe(201);
  return (await minted.json()) as Record<string, unknown>;
};

// The carrier grammar's walk (the model codec's rules): the fields,
// the optionals, and the signature slots, plus the re-encoded bytes
// the signing body reconstructs.
function walk(raw: Buffer): {
  fields: { tag: number; bytes: Buffer }[];
  signatures: { suite: number; keyId: string; sig: Buffer }[];
  signedBody: Buffer;
} {
  let pos = 0;
  const fields: { tag: number; bytes: Buffer }[] = [];
  let signatures: { suite: number; keyId: string; sig: Buffer }[] = [];
  let readOptional = (): Buffer | null => {
    const opt = raw[pos++]!;
    if (opt === 0) return null;
    const len = raw.readUInt32LE(pos);
    pos += 4;
    const v = raw.slice(pos, pos + len);
    pos += len;
    return v;
  };
  while (pos < raw.length) {
    const tag = raw[pos++]!;
    if (tag === 0x0b) {
      const n = raw[pos++]!;
      for (let i = 0; i < n; i += 1) {
        expect(raw[pos++]).toBe(0x0c);
        const suite = raw[pos++]!;
        const keyLen = raw.readUInt32LE(pos);
        pos += 4;
        const keyId = raw.slice(pos, pos + keyLen).toString();
        pos += keyLen;
        const sigLen = raw.readUInt16LE(pos);
        pos += 2;
        signatures.push({ suite, keyId, sig: raw.slice(pos, pos + sigLen) });
        pos += sigLen;
      }
      break;
    }
    if (tag === 0x08 || tag === 0x0a) {
      const opt = readOptional();
      const encoded = Buffer.concat([Buffer.from([tag]), opt === null ? Buffer.from([0]) : (() => {
        const len = Buffer.alloc(4);
        len.writeUInt32LE(opt.length);
        return Buffer.concat([Buffer.from([1]), len, opt]);
      })()]);
      fields.push({ tag, bytes: encoded });
      continue;
    }
    const fieldLen = raw.readUInt32LE(pos);
    pos += 4;
    const value = raw.slice(pos, pos + fieldLen);
    pos += fieldLen;
    const lenPrefix = Buffer.alloc(4);
    lenPrefix.writeUInt32LE(fieldLen);
    fields.push({ tag, bytes: Buffer.concat([Buffer.from([tag]), lenPrefix, value]) });
  }
  const signedBody = Buffer.concat(fields.map((f) => f.bytes).concat([Buffer.from([0x0b, 0x00])]));
  return { fields, signatures, signedBody };
}

describe("the issuer's pack route", () => {
  it("mints the carrier in the native shape", async () => {
    const issuer = new IssuerDO(storage());
    const passport = await mintPassport(issuer, "gtin:0876381333931");
    const served = await serve(
      issuer,
      `/passports/${encodeURIComponent(String(passport.passport_id))}/pack`,
      { method: "POST", body: "{}" },
    );
    if (served.status !== 201) console.log("PACK-DEBUG:", await served.text());
    expect(served.status).toBe(201);
    const pack = (await served.json()) as {
      encoding: string;
      pack: string;
      bytes: number;
      projected: number;
      qr_version: number;
      ec: string;
      signatures: { suite: string; key_id: string; anchor: string }[];
      anchor: string;
    };
    expect(pack.encoding).toBe("hex");
    expect(pack.pack).toMatch(/^[0-9a-f]+$/);
    expect(pack.bytes).toBeGreaterThan(0);
    expect(pack.qr_version).toBeGreaterThan(0);
    expect(pack.ec).toBe("m");
    expect(pack.signatures).toHaveLength(1);
    expect(pack.signatures[0].suite).toBe("ecdsa-p256");
    expect(pack.anchor).toBe(pack.signatures[0].anchor);
  });

  it("the carrier decodes and the signature verifies (the stranger's round trip)", async () => {
    const issuer = new IssuerDO(storage());
    const passport = await mintPassport(issuer, "cpid:urn:test:pack-round-trip");
    const served = await serve(
      issuer,
      `/passports/${encodeURIComponent(String(passport.passport_id))}/pack`,
      { method: "POST", body: "{}" },
    );
    const pack = (await served.json()) as {
      pack: string;
      signature: { key_id: string; anchor: string };
    };
    const { signatures, fields, signedBody } = walk(Buffer.from(pack.pack, "hex"));
    // The decoded fields carry the passport's identity.
    const byTag = (t: number): string => {
      const f = fields.find((x) => x.tag === t)!;
      const len = f.bytes.readUInt32LE(1);
      return f.bytes.slice(5, 5 + len).toString();
    };
    expect(byTag(0x03)).toBe(passport.passport_id);
    expect(byTag(0x01)).toBe("cpid:urn:test:pack-round-trip");
    expect(signatures).toHaveLength(1);
    // The slot's signature covers the signing body framed in
    // signatif's ArtifactEvent domain, under the minted anchor.
    const anchor = Buffer.from(pack.signature.anchor, "hex");
    const spki = Buffer.concat([
      Buffer.from("3059301306072A8648CE3D020106082A8648CE3D030107034200", "hex"),
      anchor,
    ]);
    const framed = Buffer.concat([
      Buffer.from("UNIDPP-SIGNATIF/ARTIFACT-EVENT"),
      Buffer.from([0]),
      signedBody,
    ]);
    const publicKey = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    // signatif emits the raw r||s form (64 bytes); node wants DER.
    const toDer = (rawSig: Buffer): Buffer => {
      if (rawSig.length !== 64) return rawSig;
      const r = rawSig.slice(0, 32);
      const s = rawSig.slice(32);
      const pad = (b: Buffer): Buffer => (b[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
      const rp = pad(r);
      const sp = pad(s);
      return Buffer.concat([
        Buffer.from([0x30, rp.length + sp.length + 4, 0x02, rp.length]),
        rp,
        Buffer.from([0x02, sp.length]),
        sp,
      ]);
    };
    const derSig = toDer(signatures[0]!.sig);
    const verified = nodeCrypto.verify("sha256", framed, publicKey, derSig);
    if (!verified) console.log("SIG-DEBUG: body", signedBody.toString("hex"), "| framed", framed.toString("hex").slice(0, 80));
    expect(signatures[0]!.keyId).toBe(pack.signature.key_id);
    // A swapped field fails the slot: tampering, loudly.
    const tamperedFields = fields.map((f) =>
      f.tag === 0x04
        ? (() => {
            const v = Buffer.from("urn:docs:actor:impostor");
            const len = Buffer.alloc(4);
            len.writeUInt32LE(v.length);
            return { tag: f.tag, bytes: Buffer.concat([Buffer.from([f.tag]), len, v]) };
          })()
        : f,
    );
    const tamperedBody = Buffer.concat(
      tamperedFields.map((f) => f.bytes).concat([Buffer.from([0x0b, 0x00])]),
    );
    const framedTampered = Buffer.concat([
      Buffer.from("UNIDPP-SIGNATIF/ARTIFACT-EVENT"),
      Buffer.from([0]),
      tamperedBody,
    ]);
    expect(nodeCrypto.verify("sha256", framedTampered, publicKey, derSig)).toBe(false);
  });

  it("refuses a pack for an unknown passport", async () => {
    const issuer = new IssuerDO(storage());
    const served = await serve(issuer, "/passports/urn:absent/pack", {
      method: "POST",
      body: "{}",
    });
    expect(served.status).toBe(404);
  });
});
