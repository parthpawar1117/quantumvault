import { describe, it, expect, beforeEach } from 'vitest';
import { FailedRequireError, MockNetworkProvider, randomUtxo, TransactionBuilder, type SpendableUtxo } from 'cashscript';
import { encodeCashAddress } from '@bitauth/libauth';
import { keygen } from '../src/wots.js';
import { budgetPadFor, loadVault, spendMessage, signSpend, toLockingBytecode } from '../src/vault.js';

const seed = new Uint8Array(32).fill(42);
const addr = (b: number) => encodeCashAddress({ prefix: 'bchtest', type: 'p2pkh', payload: new Uint8Array(20).fill(b) }).address;
const ALICE = addr(1);
const MALLORY = addr(2);
const MALLORY_TOKEN = encodeCashAddress({ prefix: 'bchtest', type: 'p2pkhWithTokens', payload: new Uint8Array(20).fill(2) }).address;
const FEE = 6000n;

describe('QuantumVault covenant (BCH_2026_05 VM)', () => {
  let provider: MockNetworkProvider;
  let vault: ReturnType<typeof loadVault>;
  let utxo: SpendableUtxo;
  const k0 = keygen(seed, 0);
  const k1 = keygen(seed, 1);
  const k2 = keygen(seed, 2);

  beforeEach(() => {
    provider = new MockNetworkProvider({ vmTarget: 'BCH_2026_05' });
    vault = loadVault(provider);
    utxo = randomUtxo({
      satoshis: 1_000_000n,
      lockingBytecode: Buffer.from(toLockingBytecode(vault.tokenAddress)).toString('hex'),
      token: { category: '11'.repeat(32), amount: 0n, nft: { capability: 'mutable', commitment: Buffer.from(k0.root).toString('hex') } },
    });
    provider.addUtxo(vault.tokenAddress, utxo);
  });

  const build = (input: SpendableUtxo, wots: Uint8Array, to: string, amount: bigint, change: bigint, nextRoot: Uint8Array, changeTo = vault.tokenAddress) =>
    new TransactionBuilder({ provider })
      .addInput(input, vault.unlock.spend(wots, budgetPadFor({ utxo: input, to, amount, change, nextRoot })))
      .addOutput({ to, amount })
      .addOutput({ to: changeTo, amount: change, token: { category: input.token!.category, amount: 0n, nft: { capability: 'mutable', commitment: Buffer.from(nextRoot).toString('hex') } } });

  it('spends with a valid WOTS signature and rotates to the next key', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots = signSpend(k0, { utxo, to: ALICE, amount: 100_000n, change, nextRoot: k1.root });
    await expect(build(utxo, wots, ALICE, 100_000n, change, k1.root).send()).resolves.toBeDefined();
  });

  it('rejects a random (forged) signature', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots = new Uint8Array(67 * 32).fill(9);
    await expect(build(utxo, wots, ALICE, 100_000n, change, k1.root).send()).rejects.toThrow(FailedRequireError);
  });

  it('rejects a mempool attacker who swaps the recipient', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots = signSpend(k0, { utxo, to: ALICE, amount: 100_000n, change, nextRoot: k1.root });
    await expect(build(utxo, wots, MALLORY, 100_000n, change, k1.root).send()).rejects.toThrow(FailedRequireError);
  });

  it('rejects an attacker who sets their own next key', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots = signSpend(k0, { utxo, to: ALICE, amount: 100_000n, change, nextRoot: k1.root });
    await expect(build(utxo, wots, ALICE, 100_000n, change, k2.root).send()).rejects.toThrow(FailedRequireError);
  });

  it('rejects change sent anywhere except back into the vault', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots = signSpend(k0, { utxo, to: ALICE, amount: 100_000n, change, nextRoot: k1.root });
    await expect(build(utxo, wots, ALICE, 100_000n, change, k1.root, MALLORY_TOKEN).send()).rejects.toThrow(FailedRequireError);
  });

  it('chains spends: key 0 is dead after rotation, key 1 works', async () => {
    const change = utxo.satoshis - 100_000n - FEE;
    const wots0 = signSpend(k0, { utxo, to: ALICE, amount: 100_000n, change, nextRoot: k1.root });
    const tx = await build(utxo, wots0, ALICE, 100_000n, change, k1.root).send();
    const next = (await provider.getUtxos(vault.tokenAddress)).find((u) => u.txid === tx.txid)! as SpendableUtxo;
    expect(next).toBeDefined();
    const change2 = next.satoshis - 50_000n - FEE;
    const reuse = signSpend(k0, { utxo: next, to: ALICE, amount: 50_000n, change: change2, nextRoot: k2.root });
    await expect(build(next, reuse, ALICE, 50_000n, change2, k2.root).send()).rejects.toThrow(FailedRequireError);
    const good = signSpend(k1, { utxo: next, to: ALICE, amount: 50_000n, change: change2, nextRoot: k2.root });
    await expect(build(next, good, ALICE, 50_000n, change2, k2.root).send()).resolves.toBeDefined();
  });

  it('binds the message to the exact outpoint (no replay across UTXOs)', () => {
    const a = spendMessage({ utxo, to: ALICE, amount: 1n, change: 1n, nextRoot: k1.root });
    const b = spendMessage({ utxo: { ...utxo, vout: utxo.vout + 1 }, to: ALICE, amount: 1n, change: 1n, nextRoot: k1.root });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(toLockingBytecode(ALICE).length).toBe(25);
  });
});
