import { readFileSync } from 'node:fs';
import { Contract, type NetworkProvider, type Utxo, type Artifact } from 'cashscript';
import { cashAddressToLockingBytecode, hexToBin } from '@bitauth/libauth';
import { digits, sha256, sign, type WotsKey } from './wots.js';

export const artifact: Artifact = JSON.parse(
  readFileSync(new URL('../artifacts/QuantumVault.json', import.meta.url), 'utf8'),
);

export const loadVault = (provider: NetworkProvider) => new Contract(artifact, [], { provider });

export function toLockingBytecode(address: string): Uint8Array {
  const r = cashAddressToLockingBytecode(address);
  if (typeof r === 'string') throw new Error(r);
  return r.bytecode;
}

const le = (n: bigint, size: number) => {
  const out = new Uint8Array(size);
  let v = n;
  for (let i = 0; i < size; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
};

export interface SpendParams {
  utxo: Pick<Utxo, 'txid' | 'vout'>;
  to: string;
  amount: bigint;
  change: bigint;
  nextRoot: Uint8Array;
}

/**
 * Exactly the message the covenant rebuilds from introspection:
 * sha256(outpointTxHash || vout_u32le || recipientLockingBytecode || amount_u64le || change_u64le || nextRoot)
 * Outpoint hashes are serialized in internal (reversed) byte order.
 */
export function spendMessage(p: SpendParams): Uint8Array {
  const parts = [
    hexToBin(p.utxo.txid).reverse(),
    le(BigInt(p.utxo.vout), 4),
    toLockingBytecode(p.to),
    le(p.amount, 8),
    le(p.change, 8),
    p.nextRoot,
  ];
  const buf = new Uint8Array(parts.reduce((s, x) => s + x.length, 0));
  let o = 0;
  for (const x of parts) { buf.set(x, o); o += x.length; }
  return sha256(buf);
}

export const signSpend = (key: WotsKey, p: SpendParams) => sign(key.sk, spendMessage(p));

/**
 * Op-cost budget padding.
 *
 * Since the May 2025 VM-limits upgrade, an input may spend up to
 * 800 * (41 + unlockingBytecodeLength) units of operation cost. Verifying a
 * WOTS signature costs (measured with scripts/measure.ts on the BCH_2026_05 VM)
 *   ~1,549,000 + ~1,361 * h     where h = sum over chains of (16 - d_i)
 * so h (517..1057) decides how many bytes of budget the wallet must buy.
 * The estimate below is deliberately conservative.
 */
export const BASE_UNLOCK_BYTES = 2409; // signature push + redeem script push + pad push prefix
export const chainHashCount = (msg: Uint8Array) => digits(msg).reduce((s, d) => s + 16 - d, 0);
export const estimateOpCost = (h: number) => 1_560_000 + 1_400 * h;

export function budgetPadFor(p: SpendParams): Uint8Array {
  const need = Math.ceil(estimateOpCost(chainHashCount(spendMessage(p))) / 800) - 41 - BASE_UNLOCK_BYTES;
  return new Uint8Array(Math.max(0, need) + 32);
}
