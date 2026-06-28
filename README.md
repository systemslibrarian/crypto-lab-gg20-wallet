# crypto-lab-gg20-wallet

## What It Is

GG20 Wallet demonstrates the GG20 threshold ECDSA protocol (Gennaro & Goldfeder, 2020) — the cryptographic foundation of institutional MPC custody used by Fireblocks, Coinbase MPC, and ZenGo. Threshold ECDSA allows t-of-n parties to jointly produce a standard ECDSA signature without any party ever holding the full private key. GG20 is significantly more complex than threshold Schnorr (FROST) because ECDSA's nonlinear nonce computation requires Paillier homomorphic encryption for joint computation. The protocol provides security against malicious adversaries with identifiable abort.

This is a **faithful, runnable** 2-of-2 implementation — not a mock-up. It performs real secp256k1 arithmetic (`@noble/curves`), real Paillier homomorphic encryption (1024-bit modulus), real **MtA** (multiplicative-to-additive) share conversion, and a real **zero-knowledge range proof** (the GG18/Lindell Σ-protocol) that demonstrably rejects the out-of-range value behind the MtA wraparound attack. The full private key `x = x₁ + x₂` and the full nonce `k = k₁ + k₂` are **never reconstructed** at any point: each party computes its own `sᵢ` locally and the signature is `s = s₁ + s₂`, verifiable as an ordinary secp256k1 signature. The core (`src/gg20.ts`) is covered by a 15-test suite (`npm test`) proving 25 random end-to-end signatures verify, MtA yields correct additive shares, a cheating party is detected, and the range proof accepts honest values while rejecting out-of-range ones and tampered proofs. Scaled down for the browser: Paillier key size, the Paillier–Blum modulus proof, the MtA discrete-log binding, and the type-5/7 blame phase (all documented in Exhibit 7). The protocol logic is the genuine article.

## When to Use It

- Institutional crypto custody requiring no single point of key compromise
- Signing on secp256k1 chains (Bitcoin, Ethereum) without key assembly
- Consumer wallets with device + server 2-of-2 signing
- Any ECDSA application requiring threshold signing without on-chain multisig
- New protocols where Schnorr is available — use FROST instead (simpler, faster, no Paillier requirement)
- Non-secp256k1 curves where ECDSA is not required
- Applications where on-chain multisig is acceptable (simpler to implement, though reveals threshold policy)
- Do NOT use this for real custody — it is a scaled-down educational 2-of-2 demo, not an audited MPC custody system.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-gg20-wallet](https://systemslibrarian.github.io/crypto-lab-gg20-wallet/)**

Eight exhibits: why ECDSA threshold is harder than Schnorr threshold, Paillier homomorphic encryption as the core MPC primitive, GG20 distributed key generation with hash-commit-then-reveal, **faithful** threshold signing via MtA over Paillier (with a "malicious Party 2" toggle and a 25-signature self-test), security analysis, a **runnable zero-knowledge range proof** that catches the out-of-range/wraparound attack live, a walkthrough of the full identifiable-abort stack (what's implemented vs. described), and real-world deployments in Fireblocks, Coinbase MPC, ZenGo, and PayPal/Curv. Each exhibit includes a "What's real / what's simplified" disclosure.

## What Can Go Wrong

- **Omitting the zero-knowledge range proofs.** Several production GG18/GG20 libraries shipped without the required range/consistency proofs and were shown to leak or fully extract private key shares — the proofs are mandatory, not optional.
- **MtA wraparound / out-of-range inputs.** If a party feeds out-of-range values into the multiplicative-to-additive conversion, it can bias the result; the range proof exists specifically to reject this.
- **Weak Paillier parameters.** Too-small or improperly generated Paillier moduli (or a missing Paillier–Blum modulus proof) break the homomorphic step the protocol relies on.
- **Nonce / randomness failures.** As with all ECDSA, predictable or reused nonce contributions can expose key material; the threshold setting adds more places for randomness to go wrong.
- **Mishandling abort and blame.** Identifiable abort only helps if the implementation actually runs the type-5/7 blame phase; silently retrying after a malicious abort can mask an active attacker.

## Real-World Usage

- **Institutional MPC custody** — Fireblocks, Coinbase MPC, and ZenGo use threshold ECDSA so no operator ever holds a full signing key.
- **Consumer and enterprise wallets** split signing across a user device and a server in a 2-of-2 arrangement, removing a single device as a single point of compromise.
- **Exchange and treasury signing** on Bitcoin and Ethereum uses threshold ECDSA to avoid revealing the signing quorum on-chain (unlike script multisig).
- **secp256k1 blockchains generally** benefit because the output is an ordinary ECDSA signature, so no chain-side changes are needed.
- **PayPal/Curv and similar platforms** brought MPC-based key management into mainstream financial custody.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-gg20-wallet
cd crypto-lab-gg20-wallet
npm install
npm run dev
```

## Related Demos

- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — threshold Schnorr (FROST), the simpler alternative when Schnorr is available.
- [crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/) — Paillier additive homomorphic encryption, the core MPC primitive in GG20.
- [crypto-lab-vss-gate](https://systemslibrarian.github.io/crypto-lab-vss-gate/) — verifiable secret sharing used in distributed key generation.
- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — single-party ECDSA and nonce-reuse attacks for contrast.
- [crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/) — threshold signing in the post-quantum setting.

## Architecture

- `src/gg20.ts` — the DOM-free cryptographic core: Paillier (Miller–Rabin keygen, encrypt/decrypt), MtA share conversion, GG20 DKG and signing. This is the single source of truth, imported by both the UI and the tests.
- `src/main.ts` — the UI: rendering, state, and event wiring only.
- `test/gg20.test.ts` — Node built-in test runner suite exercising the same module the browser runs.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
