/**
 * Winternitz One-Time Signatures (WOTS), w = 16, n = 32 bytes, SHA-256.
 *
 * Hash-based signatures rely only on the preimage resistance of SHA-256, so
 * Shor's algorithm (which breaks ECDSA/Schnorr) does not apply. Grover's
 * algorithm only halves the security level: 256-bit hashes keep ~128-bit
 * post-quantum security.
 *
 * Layout: 64 message digits (one per nibble of the 32-byte message) plus
 * 3 checksum digits. The checksum stops an attacker from "advancing" chains
 * to forge a different message from an observed signature.
 *
 * The public key is compressed to a single 32-byte root:
 *   root = fold(acc = empty; acc = sha256(acc || pk_i))
 * which is exactly what the on-chain contract recomputes.
 */
import { createHash } from 'node:crypto';

export const W = 16;
export const LEN1 = 64;
export const LEN2 = 3;
export const WOTS_LEN = LEN1 + LEN2;
export const N = 32;

export const sha256 = (b: Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(b).digest());

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

const chain = (x: Uint8Array, steps: number): Uint8Array => {
  let y = x;
  for (let i = 0; i < steps; i++) y = sha256(y);
  return y;
};

/** 64 nibbles (high nibble first) + base-16 checksum of sum(15 - d). */
export function digits(msg: Uint8Array): number[] {
  if (msg.length !== N) throw new Error('message must be 32 bytes');
  const d: number[] = [];
  for (const byte of msg) d.push(byte >> 4, byte & 0x0f);
  const csum = d.reduce((s, x) => s + (W - 1 - x), 0); // max 960 < 16^3
  d.push((csum >> 8) & 0xf, (csum >> 4) & 0xf, csum & 0xf);
  return d;
}

export function rootFromPk(pk: Uint8Array[]): Uint8Array {
  let acc: Uint8Array = new Uint8Array(0);
  for (const p of pk) acc = sha256(concat(acc, p));
  return acc;
}

export interface WotsKey { index: number; sk: Uint8Array[]; pk: Uint8Array[]; root: Uint8Array }

/** Deterministic key #index from a 32-byte seed: sk_i = sha256(seed || index_u32 || i_u8). */
export function keygen(seed: Uint8Array, index: number): WotsKey {
  const idx = new Uint8Array(4);
  new DataView(idx.buffer).setUint32(0, index);
  const sk = Array.from({ length: WOTS_LEN }, (_, i) => sha256(concat(seed, idx, Uint8Array.of(i))));
  const pk = sk.map((s) => chain(s, W - 1));
  return { index, sk, pk, root: rootFromPk(pk) };
}

/** Signature = 67 chain elements, each advanced d_i steps from the secret. */
export function sign(sk: Uint8Array[], msg: Uint8Array): Uint8Array {
  const d = digits(msg);
  return concat(...sk.map((s, i) => chain(s, d[i])));
}

/** Finish every chain (15 - d_i more steps) and fold into the root. */
export function recoverRoot(sig: Uint8Array, msg: Uint8Array): Uint8Array {
  if (sig.length !== WOTS_LEN * N) throw new Error('bad signature length');
  const d = digits(msg);
  const pk = d.map((di, i) => chain(sig.slice(i * N, i * N + N), W - 1 - di));
  return rootFromPk(pk);
}

export function verify(sig: Uint8Array, msg: Uint8Array, root: Uint8Array): boolean {
  const r = recoverRoot(sig, msg);
  return r.length === root.length && r.every((b, i) => b === root[i]);
}
