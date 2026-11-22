/** Measures real VM op-cost of a QuantumVault spend against the BCH 2026 limits. */
import { MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { createVirtualMachine } from '../node_modules/cashscript/dist/libauth-template/utils.js';
import { decodeTransaction, hexToBin, encodeCashAddress } from '../node_modules/cashscript/node_modules/@bitauth/libauth/build/index.js';
import { keygen, digits } from '../src/wots.js';
import { loadVault, signSpend, spendMessage, toLockingBytecode } from '../src/vault.js';

const provider = new MockNetworkProvider({ vmTarget: 'BCH_2026_05' });
const vault = loadVault(provider);
const to = encodeCashAddress({ prefix: 'bchtest', type: 'p2pkh', payload: new Uint8Array(20).fill(1) }).address;
const k0 = keygen(new Uint8Array(32).fill(42), 0), k1 = keygen(new Uint8Array(32).fill(42), 1);
const vm = createVirtualMachine('BCH_2026_05');

for (let t = 0; t < Number(process.argv[2] ?? 5); t++) {
  const utxo = randomUtxo({ satoshis: 1_000_000n, lockingBytecode: Buffer.from(toLockingBytecode(vault.tokenAddress)).toString('hex'),
    token: { category: '11'.repeat(32), amount: 0n, nft: { capability: 'mutable', commitment: Buffer.from(k0.root).toString('hex') } } });
  const change = utxo.satoshis - 100_000n - 8000n;
  const p = { utxo, to, amount: 100_000n, change, nextRoot: k1.root };
  const hashes = digits(spendMessage(p)).reduce((s, d) => s + 16 - d, 0);
  const hex = new TransactionBuilder({ provider }).addInput(utxo, vault.unlock.spend(signSpend(k0, p), new Uint8Array(Number(process.argv[3] ?? 0))))
    .addOutput({ to, amount: 100_000n })
    .addOutput({ to: vault.tokenAddress, amount: change, token: { category: utxo.token!.category, amount: 0n, nft: { capability: 'mutable', commitment: Buffer.from(k1.root).toString('hex') } } })
    .build();
  const tx = decodeTransaction(hexToBin(hex));
  if (typeof tx === 'string') throw new Error(tx);
  const sourceOutputs = [{ lockingBytecode: toLockingBytecode(vault.tokenAddress), valueSatoshis: utxo.satoshis,
    token: { category: hexToBin(utxo.token!.category), amount: 0n, nft: { capability: 'mutable' as const, commitment: k0.root } } }];
  const state: any = vm.evaluate({ inputIndex: 0, sourceOutputs, transaction: tx });
  const m = state.metrics;
  const unlockLen = tx.inputs[0].unlockingBytecode.length;
  console.log(`chainHashes=${hashes} txBytes=${hex.length / 2} unlock=${unlockLen} opCost=${m.operationCost} budget=${(41 + unlockLen) * 800} hashIters=${m.hashDigestIterations} err=${state.error ?? 'none'}`);
}
