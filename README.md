# crypto-lab-gg20-wallet

## 1. What It Is

GG20 Wallet demonstrates the GG20 threshold ECDSA protocol (Gennaro & Goldfeder, 2020) — the cryptographic foundation of institutional MPC custody used by Fireblocks, Coinbase MPC, and ZenGo. Threshold ECDSA allows t-of-n parties to jointly produce a standard ECDSA signature without any party ever holding the full private key. GG20 is significantly more complex than threshold Schnorr (FROST) because ECDSA's nonlinear nonce computation requires Paillier homomorphic encryption for joint computation. The protocol provides security against malicious adversaries with identifiable abort.

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

Six exhibits: why ECDSA threshold is harder than Schnorr threshold, Paillier homomorphic encryption as the core MPC primitive, GG20 distributed key generation with commitment exchange, threshold signing protocol using Paillier for joint nonce computation, security analysis including range proofs and identifiable abort, and real-world deployments in Fireblocks, Coinbase MPC, ZenGo, and PayPal/Curv.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-gg20-wallet
cd crypto-lab-gg20-wallet
npm install
npm run dev
```

## 5. Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — browser-based cryptography demos spanning 2,500 years of cryptographic history to NIST FIPS 2024 post-quantum standards.

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31