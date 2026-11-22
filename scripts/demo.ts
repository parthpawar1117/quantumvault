/**
 * End-to-end QuantumVault story on a local BCH_2026_05 mock network:
 * fund a vault, make three payments (rotating one-time keys), and watch
 * three attacks fail inside the covenant.
 */
import { MockNetworkProvider, randomUtxo, TransactionBuilder, type SpendableUtxo } from 'cashscript';
import { encodeCashAddress } from '@bitauth/libauth';
import { keygen, type WotsKey } from '../src/wots.js';
import { budgetPadFor, chainHashCount, loadVault, signSpend, spendMessage, toLockingBytecode } from '../src/vault.js';

const provider = new MockNetworkProvider({ vmTarget: 'BCH_2026_05' });
const vault = loadVault(provider);
const addr = (b: number, type: 'p2pkh' | 'p2pkhWithTokens' = 'p2pkh') =>
  encodeCashAddress({ prefix: 'bchtest', type, payload: new Uint8Array(20).fill(b) }).address;
const [ALICE, BOB, CAROL, MALLORY] = [addr(1), addr(3), addr(4), addr(2)];
const seed = crypto.getRandomValues(new Uint8Array(32));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const short = (s: string) => `${s.slice(0, 10)}…${s.slice(-6)}`;

const keys: WotsKey[] = [0, 1, 2, 3].map((i) => keygen(seed, i));
let utxo: SpendableUtxo = randomUtxo({
  satoshis: 10_000_000n,
  lockingBytecode: hex(toLockingBytecode(vault.tokenAddress)),
  token: { category: hex(crypto.getRandomValues(new Uint8Array(32))), amount: 0n, nft: { capability: 'mutable', commitment: hex(keys[0].root) } },
});
provider.addUtxo(vault.tokenAddress, utxo);

console.log('\n QUANTUMVAULT: post-quantum Bitcoin Cash vault (BCH 2026 VM)\n');
console.log(` vault address   ${vault.tokenAddress}`);
console.log(` balance         ${utxo.satoshis} sats`);
console.log(` key #0 root     ${short(hex(keys[0].root))}  (stored in the vault NFT)`);
console.log(` no ECDSA/Schnorr key controls these coins: SHA-256 only\n`);

const tx = (input: SpendableUtxo, wots: Uint8Array, to: string, amount: bigint, change: bigint, nextRoot: Uint8Array, changeTo = vault.tokenAddress) =>
  new TransactionBuilder({ provider })
    .addInput(input, vault.unlock.spend(wots, budgetPadFor({ utxo: input, to, amount, change, nextRoot })))
    .addOutput({ to, amount })
    .addOutput({ to: changeTo, amount: change, token: { category: input.token!.category, amount: 0n, nft: { capability: 'mutable', commitment: hex(nextRoot) } } });

async function attempt(label: string, fn: () => Promise<unknown>) {
  try { await fn(); console.log(`   ✗ ${label}: ACCEPTED (bug!)`); }
  catch (e: any) { console.log(`   ✓ ${label}: rejected by covenant (${String(e.message).split('\n')[0].slice(0, 70)})`); }
}

const payments: [string, string, bigint][] = [['Alice', ALICE, 1_500_000n], ['Bob', BOB, 700_000n], ['Carol', CAROL, 2_000_000n]];
for (let i = 0; i < payments.length; i++) {
  const [name, to, amount] = payments[i];
  const fee = 6_000n;
  const change = utxo.satoshis - amount - fee;
  const p = { utxo, to, amount, change, nextRoot: keys[i + 1].root };
  const wots = signSpend(keys[i], p);
  console.log(` payment ${i + 1}: ${amount} sats -> ${name}, signed with one-time key #${i}`);

  if (i === 0) {
    console.log('   attacks on this exact signed transaction:');
    await attempt('mempool attacker redirects payment to Mallory', () => tx(utxo, wots, MALLORY, amount, change, keys[1].root).send());
    await attempt('attacker installs their own next key', () => tx(utxo, wots, to, amount, change, keygen(new Uint8Array(32), 9).root).send());
    await attempt('attacker sends the vault change to themselves', () => tx(utxo, wots, to, amount, change, keys[1].root, addr(2, 'p2pkhWithTokens')).send());
    await attempt('forged signature (random bytes)', () => tx(utxo, new Uint8Array(2144).fill(7), to, amount, change, keys[1].root).send());
  }
  if (i === 1) {
    const reuse = signSpend(keys[0], p);
    await attempt('reuse of burned key #0', () => tx(utxo, reuse, to, amount, change, keys[2].root).send());
  }

  const pad = budgetPadFor(p);
  const sent = await tx(utxo, wots, to, amount, change, keys[i + 1].root).send();
  utxo = (await provider.getUtxos(vault.tokenAddress)).find((u) => u.txid === sent.txid)! as SpendableUtxo;
  console.log(`   ✓ confirmed ${short(sent.txid)}  size ${sent.hex.length / 2} B  chain hashes ${chainHashCount(spendMessage(p))}  budget pad ${pad.length} B`);
  console.log(`   vault now ${utxo.satoshis} sats, NFT rotated to key #${i + 1} root ${short(utxo.token!.nft!.commitment)}\n`);
}
console.log(' done: 3 quantum-safe payments, 5 attacks rejected on-chain.\n');
