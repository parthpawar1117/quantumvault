# QuantumVault

**A post-quantum Bitcoin Cash vault.** Coins are locked by a covenant that only accepts a
**Winternitz one-time signature (WOTS)**, verified on-chain with nothing but SHA-256. No
ECDSA or Schnorr key controls the coins, so a quantum computer running Shor's algorithm
has nothing to break. Every spend forces the vault to rotate to a fresh one-time key.

Built for **BCH BLAZE 2026**. The verifier depends on the **May 2026 BCH upgrade** (loops),
the **2025 VM limits** (large stack items, op-cost budget) and **CashTokens** (NFT state).

- Live demo (in-browser signer and attacks): https://parthpawarsnap11-create.github.io/quantumvault/
- Contract: [`contracts/QuantumVault.cash`](contracts/QuantumVault.cash)

```
$ npm install && npm test        # 12 tests on the BCH_2026_05 VM
$ npm run demo                   # 3 payments, 5 attacks rejected
```

## Why

Every BCH, BTC and ETH output today is ultimately guarded by secp256k1. A large enough
quantum computer breaks it, and coins with exposed public keys are the first at risk.
Hash-based signatures are the conservative answer (NIST standardized SPHINCS+/SLH-DSA,
built from the same idea), but they need far more computation than a classic Bitcoin
script allowed. Since BCH's 2025 and 2026 upgrades, that computation fits in a normal
transaction. QuantumVault shows it working today.

## How it works

```
vault UTXO  ── mutable NFT, commitment = root(key #n)
   │  spend(wots, budgetPad)
   ├─ output 0: payment to any address, no tokens
   └─ output 1: same contract, same NFT category, commitment = root(key #n+1)
```

1. **Keys.** WOTS with w = 16 and n = 32 bytes: 64 message chains plus 3 checksum chains,
   67 in total. A key's 67 chain ends are folded into one 32-byte root:
   `acc = sha256(acc ‖ pk_i)`.
2. **Message.** `sha256(outpointTxHash ‖ outpointIndex ‖ recipientLockingBytecode ‖ amount ‖ change ‖ nextRoot)`.
   The covenant rebuilds it from transaction introspection, so the signature covers every
   field an attacker might want to change.
3. **Verify.** A `for` loop over 67 chains, each finished with a `do … while` hash loop
   (16 − d steps), folded into the root and compared with the NFT commitment.
4. **Rotate.** Output 1 must be the same contract with the same NFT category, and its
   commitment (the next key root) is signed. Each one-time key therefore signs exactly
   once, and the old key is dead the moment the spend confirms.

### The op-cost budget pad

The 2025 VM-limits upgrade gives each input `800 × (41 + unlockingBytecodeLength)` units
of operation cost. Measured on the `BCH_2026_05` VM ([`scripts/measure.ts`](scripts/measure.ts)):

| chain hashes h | op cost | hash iterations |
|---:|---:|---:|
| 517 | 2,252,846 | 658 |
| 592 | 2,354,900 | 733 |
| 667 | 2,456,961 | 808 |
| 1,057 (worst case) | ≈ 2.99M (model) | ≈ 1,200 |

So cost ≈ 1.55M + 1,361·h. The wallet appends a `budgetPad` of ignored bytes, sized by
`budgetPadFor()`, to buy exactly the budget it needs: about 500 B for a typical spend and
about 1.4 kB in the worst case. A full spend is 3 to 4.3 kB, well within standardness, for
a fee of a few thousand satoshis.

Optimizations that mattered:
- Using chain length 16 (verifier hashes 16 − d ≥ 1 times) let the inner loop be a
  `do … while` with no `IF`. That cut it from 17 to 11 opcodes per hash.
- Consuming the signature with `split(32)` instead of `slice` on every step.

## Tests

`npm test` runs vitest against CashScript's `MockNetworkProvider` with `vmTarget: 'BCH_2026_05'`:

- WOTS: digit and checksum layout, deterministic keygen, valid/invalid message, tampered signature
- Covenant: valid spend rotates the key ✓, forged signature ✗, recipient swapped in the
  mempool ✗, attacker's next key ✗, change sent outside the vault ✗, reuse of a burned
  key ✗ while the rotated key ✓, outpoint binding

Every rejection is asserted as a `FailedRequireError`, so failures come from the
contract, not from fee or builder checks.

## Threat model and limits

- **Quantum adversary:** forging WOTS requires SHA-256 preimages, about 2¹²⁸ work even with
  Grover's algorithm.
- **Front-running:** the signature commits to all outputs and the next key.
- **One-time keys:** the covenant enforces rotation, and the outpoint is in the message. The
  wallet must never sign two different messages for the same vault state.
- **Proof of concept, not audited.** Production would add WOTS+ per-chain tweaks
  (multi-target resistance), an XMSS-style Merkle tree so one root covers many keys, a
  `sweep` path to close a vault, and a hardware signer. Funding the vault and creating the
  NFT still uses a normal wallet transaction; from then on the coins are hash-locked only.

## Layout

```
contracts/QuantumVault.cash   covenant (CashScript 0.14)
artifacts/QuantumVault.json   compiled artifact
src/wots.ts                   WOTS keygen / sign / recover
src/vault.ts                  message layout, signing, budget padding
test/                         vitest suites
scripts/demo.ts               end-to-end story on the mock network
scripts/measure.ts            op-cost measurement on the 2026 VM
docs/index.html               static in-browser demo (GitHub Pages)
```

License: MIT
