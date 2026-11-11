// The RFC 6962 Merkle tree (REARCH R12 S3): the port of the log
// service's cached-levels tree. The leaf and node hashes come from
// the wasm core (the signatif reference constants 0x01/0x02), so the
// roots — and every proof derived from them — are the native bytes.

export type Hash32 = Uint8Array;

export interface ProofNode {
  sibling: Hash32;
  side: "left" | "right";
}

export type Sha256 = (data: Uint8Array) => Hash32;

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

// The transparency constants (signatif::anchor): the same prefixes the
// native estate hashes with.
export function leafHash(sha: Sha256, entry: Hash32): Hash32 {
  return sha(concat(new Uint8Array([0x01]), entry));
}

export function nodeHash(sha: Sha256, left: Hash32, right: Hash32): Hash32 {
  return sha(concat(new Uint8Array([0x02]), left, right));
}

// The RFC 6962 split point: the largest power of two strictly smaller
// than n (n >= 2).
const split = (n: number): number => 1 << Math.floor(Math.log2(n - 1));

export class MerkleTree {
  private levels: Hash32[][] = [[]];
  size = 0;

  constructor(private readonly sha: Sha256) {}

  append(entry: Hash32): void {
    this.levels[0].push(leafHash(this.sha, entry));
    this.size += 1;
    // Every trailing zero bit of the new size is a subtree that just
    // completed; fold them up level by level.
    const foldCount = Math.log2(this.size & -this.size);
    while (this.levels.length <= foldCount) {
      this.levels.push([]);
    }
    for (let k = 0; k < foldCount; k += 1) {
      const level = this.levels[k];
      const n = level.length;
      const h = nodeHash(this.sha, level[n - 2], level[n - 1]);
      this.levels[k + 1].push(h);
    }
  }

  rootAtSize(s: number): Hash32 | null {
    if (s === 0) return null;
    let acc: Hash32 | null = null;
    for (let k = 0; k < 32; k += 1) {
      if (((s >> k) & 1) === 0) continue;
      const h = this.levels[k][(s >> k) - 1];
      acc = acc === null ? h : nodeHash(this.sha, h, acc);
    }
    return acc;
  }

  root(): Hash32 | null {
    return this.rootAtSize(this.size);
  }

  private subtreeHash(k: number, j: number): Hash32 {
    return this.levels[k][j];
  }

  private rangeHash(lo: number, len: number): Hash32 {
    if ((len & (len - 1)) === 0) {
      return this.subtreeHash(Math.log2(len), lo / len);
    }
    const k = split(len);
    const left = this.rangeHash(lo, k);
    const right = this.rangeHash(lo + k, len - k);
    return nodeHash(this.sha, left, right);
  }

  private pathInto(m: number, lo: number, len: number, path: ProofNode[]): void {
    if (len === 1) return;
    const k = split(len);
    if (m - lo < k) {
      this.pathInto(m, lo, k, path);
      const sibling = this.rangeHash(lo + k, len - k);
      path.push({ sibling, side: "right" });
    } else {
      this.pathInto(m, lo + k, len - k, path);
      const sibling = this.subtreeHash(Math.log2(k), lo / k);
      path.push({ sibling, side: "left" });
    }
  }

  inclusionPath(m: number, s: number): ProofNode[] {
    const path: ProofNode[] = [];
    this.pathInto(m, 0, s, path);
    return path;
  }

  private subProof(
    m: number,
    lo: number,
    len: number,
    anchored: boolean,
    path: Hash32[],
  ): void {
    if (m === len) {
      if (!anchored) path.push(this.rangeHash(lo, len));
      return;
    }
    const k = split(len);
    if (m <= k) {
      this.subProof(m, lo, k, anchored, path);
      path.push(this.rangeHash(lo + k, len - k));
    } else {
      this.subProof(m - k, lo + k, len - k, false, path);
      path.push(this.rangeHash(lo, k));
    }
  }

  consistencyPath(oldSize: number): Hash32[] {
    const path: Hash32[] = [];
    if (oldSize > 0) {
      this.subProof(oldSize, 0, this.size, true, path);
    }
    return path;
  }
}
