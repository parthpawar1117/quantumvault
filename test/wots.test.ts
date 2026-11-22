import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { WOTS_LEN, digits, keygen, sign, recoverRoot, verify } from '../src/wots.js';

const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const seed = new Uint8Array(32).fill(7);
const msg = sha(new TextEncoder().encode('pay 0.1 BCH to alice'));

describe('WOTS (w=16, n=32)', () => {
  it('splits a 32-byte message into 64 nibbles plus a 3-digit checksum', () => {
    const d = digits(msg);
    expect(d).toHaveLength(WOTS_LEN);
    expect(WOTS_LEN).toBe(67);
    expect(d.every((x) => x >= 0 && x < 16)).toBe(true);
    const csum = d.slice(0, 64).reduce((s, x) => s + (15 - x), 0);
    expect(d[64] * 256 + d[65] * 16 + d[66]).toBe(csum);
  });

  it('derives keys deterministically from seed and index', () => {
    expect(keygen(seed, 0).root).toEqual(keygen(seed, 0).root);
    expect(keygen(seed, 0).root).not.toEqual(keygen(seed, 1).root);
  });

  it('verifies a valid signature', () => {
    const k = keygen(seed, 0);
    const s = sign(k.sk, msg);
    expect(s).toHaveLength(67 * 32);
    expect(recoverRoot(s, msg)).toEqual(k.root);
    expect(verify(s, msg, k.root)).toBe(true);
  });

  it('rejects a signature over a different message', () => {
    const k = keygen(seed, 0);
    const s = sign(k.sk, msg);
    const other = sha(new TextEncoder().encode('pay 0.1 BCH to mallory'));
    expect(verify(s, other, k.root)).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const k = keygen(seed, 0);
    const s = sign(k.sk, msg);
    s[100] ^= 1;
    expect(verify(s, msg, k.root)).toBe(false);
  });
});
