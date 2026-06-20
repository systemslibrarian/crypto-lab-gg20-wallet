# crypto-lab-gg20-wallet

## 1. What It Is

GG20 Wallet demonstrates the GG20 threshold ECDSA protocol (Gennaro & Goldfeder, 2020) — the cryptographic foundation of institutional MPC custody used by Fireblocks, Coinbase MPC, and ZenGo. Threshold ECDSA allows t-of-n parties to jointly produce a standard ECDSA signature without any party ever holding the full private key. GG20 is significantly more complex than threshold Schnorr (FROST) because ECDSA's nonlinear nonce computation requires Paillier homomorphic encryption for joint computation. The protocol provides security against malicious adversaries with identifiable abort.

This is a **faithful, runnable** 2-of-2 implementation — not a mock-up. It performs real secp256k1 arithmetic (`@noble/curves`), real Paillier homomorphic encryption (1024-bit modulus), real **MtA** (multiplicative-to-additive) share conversion, and a real **zero-knowledge range proof** (the GG18/Lindell Σ-protocol) that demonstrably rejects the out-of-range value behind the MtA wraparound attack. The full private key `x = x₁ + x₂` and the full nonce `k = k₁ + k₂` are **never reconstructed** at any point: each party computes its own `sᵢ` locally and the signature is `s = s₁ + s₂`, verifiable as an ordinary secp256k1 signature. The core (`src/gg20.ts`) is covered by a 15-test suite (`npm test`) proving 25 random end-to-end signatures verify, MtA yields correct additive shares, a cheating party is detected, and the range proof accepts honest values while rejecting out-of-range ones and tampered proofs. Scaled down for the browser: Paillier key size, the Paillier–Blum modulus proof, the MtA discrete-log binding, and the type-5/7 blame phase (all documented in Exhibit 7). The protocol logic is the genuine article.

## 2. When to Use It

- ✅ Institutional crypto custody requiring no single point of key compromise
- ✅ Signing on secp256k1 chains (Bitcoin, Ethereum) without key assembly
- ✅ Consumer wallets with device + server 2-of-2 signing
- ✅ Any ECDSA application requiring threshold signing without on-chain multisig
- ❌ New protocols where Schnorr is available — use FROST instead (simpler, faster, no Paillier requirement)
- ❌ Non-secp256k1 curves where ECDSA is not required
- ❌ Applications where on-chain multisig is acceptable (simpler to implement, though reveals threshold policy)

## 3. Live Demo

Link: https://systemslibrarian.github.io/crypto-lab-gg20-wallet/

Eight exhibits: why ECDSA threshold is harder than Schnorr threshold, Paillier homomorphic encryption as the core MPC primitive, GG20 distributed key generation with hash-commit-then-reveal, **faithful** threshold signing via MtA over Paillier (with a "malicious Party 2" toggle and a 25-signature self-test), security analysis, a **runnable zero-knowledge range proof** that catches the out-of-range/wraparound attack live, a walkthrough of the full identifiable-abort stack (what's implemented vs. described), and real-world deployments in Fireblocks, Coinbase MPC, ZenGo, and PayPal/Curv. Each exhibit includes a "What's real / what's simplified" disclosure.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-gg20-wallet
cd crypto-lab-gg20-wallet
npm install
npm run dev      # start the demo
npm test         # prove the GG20 core is correct (11 tests)
npm run build    # typecheck + production build
```

## Architecture

- `src/gg20.ts` — the DOM-free cryptographic core: Paillier (Miller–Rabin keygen, encrypt/decrypt), MtA share conversion, GG20 DKG and signing. This is the single source of truth, imported by both the UI and the tests.
- `src/main.ts` — the UI: rendering, state, and event wiring only.
- `test/gg20.test.ts` — Node built-in test runner suite exercising the same module the browser runs.

## 5. Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — browser-based cryptography demos spanning 2,500 years of cryptographic history to NIST FIPS 2024 post-quantum standards.

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31