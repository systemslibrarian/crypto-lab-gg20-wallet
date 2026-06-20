// Pure GG20 threshold-ECDSA core — no DOM, no styling. Imported by the UI
// (main.ts) and exercised directly by the test suite (test/gg20.test.ts).
//
// This is a faithful 2-of-2 GG20 signer: real secp256k1 arithmetic, real
// Paillier homomorphic encryption, real MtA share conversion. The full private
// key x = x₁ + x₂ and the full nonce k = k₁ + k₂ are NEVER reconstructed.
import { secp256k1 } from '@noble/curves/secp256k1.js';

export type PaillierKeyPair = {
  p: bigint;
  q: bigint;
  n: bigint;
  nsq: bigint;
  g: bigint;
  lambda: bigint;
  mu: bigint;
};

// One signer in the 2-of-2 wallet. Holds an additive key share xᵢ and a
// long-term Paillier keypair. cX is Encᵢ(xᵢ) published once at DKG and reused
// during every signing — the only thing the other party ever sees of xᵢ.
export type Party = {
  x: bigint;
  X: string; // xᵢ·G compressed hex
  paillier: PaillierKeyPair;
  cX: bigint; // Enc_pkᵢ(xᵢ)
  commitment: string; // H(Xᵢ), revealed before Xᵢ
};

// Everything produced by one run of the GG20 signing protocol. Each field is
// labelled with which party physically holds it, so the UI can prove the full
// secret is never assembled in one place.
export type SignResult = {
  cheat: boolean;
  Gamma1: string;
  Gamma2: string;
  delta1: bigint; // P1's additive share of δ = k·γ
  delta2: bigint; // P2's additive share of δ
  delta: bigint; // revealed: δ = k·γ
  sigma1: bigint; // P1's additive share of σ = k·x  (never leaves P1)
  sigma2: bigint; // P2's additive share of σ          (never leaves P2)
  R: string; // R = δ⁻¹·Γ  = k⁻¹·G
  r: bigint;
  s1: bigint;
  s2: bigint;
  s: bigint;
  signatureHex: string;
  verified: boolean;
  abortReason?: string;
};

export const ORDER = secp256k1.Point.Fn.ORDER;
export const BASE = secp256k1.Point.BASE;
export const HALF_ORDER = ORDER >> 1n;

// Production GG20 uses ≥2048-bit Paillier. We use 1024-bit (two 512-bit primes)
// so in-browser keygen stays fast while the modulus is still large enough for a
// *faithful* MtA: cross products kᵢ·γⱼ < ORDER² < 2⁵¹² plus the 2⁵¹² blinding
// term never wrap modulo n ≈ 2¹⁰²⁴. A 64-bit toy modulus (as in many demos)
// physically cannot hold these products — which is why those demos fake the
// signing step. This one does not.
export const PAILLIER_PRIME_BITS = 512;
export const MTA_BLIND_BITS = 512;

const textEncoder = new TextEncoder();

export const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const hexToBytes = (v: string): Uint8Array => {
  if (v.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(v.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(v.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const to32Hex = (x: bigint): string => x.toString(16).padStart(64, '0');
export const mod = (a: bigint, n: bigint): bigint => ((a % n) + n) % n;

const egcd = (a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } => {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const { g, x, y } = egcd(b, a % b);
  return { g, x: y, y: x - (a / b) * y };
};

export const modInv = (a: bigint, n: bigint): bigint => {
  const { g, x } = egcd(mod(a, n), n);
  if (g !== 1n) throw new Error('inverse does not exist');
  return mod(x, n);
};

export const gcd = (a: bigint, b: bigint): bigint => {
  let x = a;
  let y = b;
  while (y !== 0n) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
};

const lcm = (a: bigint, b: bigint): bigint => (a / gcd(a, b)) * b;

export const modPow = (base: bigint, exp: bigint, n: bigint): bigint => {
  let b = mod(base, n);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = mod(out * b, n);
    b = mod(b * b, n);
    e >>= 1n;
  }
  return out;
};

// ---------- Cryptographic randomness ----------

export const randBits = (bits: number): bigint => {
  const bytes = Math.ceil(bits / 8);
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  let x = 0n;
  for (const byte of arr) x = (x << 8n) | BigInt(byte);
  return x >> BigInt(bytes * 8 - bits);
};

export const randBelow = (n: bigint): bigint => {
  const bits = n.toString(2).length;
  let r = randBits(bits);
  while (r >= n) r = randBits(bits);
  return r;
};

export const randomScalar = (): bigint => mod(BigInt(`0x${hex(secp256k1.utils.randomSecretKey())}`), ORDER);

// ---------- Prime generation (Miller–Rabin) ----------

const SMALL_PRIMES: bigint[] = (() => {
  const sieve: boolean[] = new Array(1000).fill(true);
  const primes: bigint[] = [];
  for (let i = 2; i < 1000; i += 1) {
    if (!sieve[i]) continue;
    primes.push(BigInt(i));
    for (let j = i * i; j < 1000; j += i) sieve[j] = false;
  }
  return primes;
})();

export const isProbablePrime = (n: bigint, rounds = 24): boolean => {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1n;
  }
  for (let i = 0; i < rounds; i += 1) {
    const a = 2n + randBelow(n - 3n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let witnessed = true;
    for (let r = 1n; r < s; r += 1n) {
      x = mod(x * x, n);
      if (x === n - 1n) {
        witnessed = false;
        break;
      }
    }
    if (witnessed) return false;
  }
  return true;
};

const genPrime = (bits: number): bigint => {
  for (;;) {
    let candidate = randBits(bits);
    candidate |= 1n; // odd
    candidate |= 1n << BigInt(bits - 1); // full bit length
    if (isProbablePrime(candidate)) return candidate;
  }
};

// ---------- Paillier ----------

export const paillierKeygen = (bits: number): PaillierKeyPair => {
  const p = genPrime(bits);
  let q = genPrime(bits);
  while (q === p) q = genPrime(bits);
  const n = p * q;
  const nsq = n * n;
  const g = n + 1n; // standard simplification
  const lambda = lcm(p - 1n, q - 1n);
  const lOfG = (modPow(g, lambda, nsq) - 1n) / n;
  const mu = modInv(lOfG, n);
  return { p, q, n, nsq, g, lambda, mu };
};

// Encrypt and also return the randomness r — needed as a witness by the range
// proof (Enc(m) = (1+N)^m · r^N mod N²).
export const paillierEncryptWithR = (m: bigint, key: PaillierKeyPair): { c: bigint; r: bigint } => {
  let r = randBelow(key.n - 1n) + 1n;
  while (gcd(r, key.n) !== 1n) r = randBelow(key.n - 1n) + 1n;
  const gm = modPow(key.g, mod(m, key.n), key.nsq);
  const rn = modPow(r, key.n, key.nsq);
  return { c: mod(gm * rn, key.nsq), r };
};

export const paillierEncrypt = (m: bigint, key: PaillierKeyPair): bigint =>
  paillierEncryptWithR(m, key).c;

export const paillierDecrypt = (c: bigint, key: PaillierKeyPair): bigint => {
  const x = modPow(c, key.lambda, key.nsq);
  const lx = (x - 1n) / key.n;
  return mod(lx * key.mu, key.n);
};

// MtA — Multiplicative-to-Additive share conversion, the heart of GG20.
//
// The encryptor owns `key` and a secret `encSecret`; the exponentiator owns a
// secret `expSecret`. They end up holding additive shares (alpha, beta) with
//     alpha + beta ≡ encSecret · expSecret   (mod ORDER)
// and neither learns the other's secret.
//
//  1. Encryptor publishes  c = Enc(encSecret)         (reused from DKG if given)
//  2. Exponentiator picks blind β', returns  c^expSecret · Enc(β')
//                                           = Enc(encSecret·expSecret + β')
//  3. Encryptor decrypts → alpha = encSecret·expSecret + β'   (no wrap mod n)
//  4. Exponentiator keeps beta = -β'
//
// No wrap-around: encSecret·expSecret < ORDER² < 2⁵¹² and β' < 2⁵¹², so the sum
// is < 2⁵¹³ ≪ n ≈ 2¹⁰²⁴, and the additive relation holds over the integers.
export const mta = (
  encSecret: bigint,
  expSecret: bigint,
  key: PaillierKeyPair,
  precomputedEnc?: bigint
): { alpha: bigint; beta: bigint } => {
  const enc = precomputedEnc ?? paillierEncrypt(mod(encSecret, key.n), key);
  const blind = randBits(MTA_BLIND_BITS);
  const c = mod(modPow(enc, mod(expSecret, key.n), key.nsq) * paillierEncrypt(blind, key), key.nsq);
  const alpha = mod(paillierDecrypt(c, key), ORDER);
  const beta = mod(-blind, ORDER);
  return { alpha, beta };
};

// ---------- secp256k1 helpers ----------

export const scalarToPointHex = (x: bigint): string => hex(BASE.multiply(x).toBytes(true));
export const pointX = (pointHex: string): bigint => mod(secp256k1.Point.fromHex(pointHex).toAffine().x, ORDER);
export const pointAddHex = (aHex: string, bHex: string): string =>
  hex(secp256k1.Point.fromHex(aHex).add(secp256k1.Point.fromHex(bHex)).toBytes(true));

export const sha256Bytes = async (input: string): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', textEncoder.encode(input)));
export const sha256Hex = async (input: string): Promise<string> => hex(await sha256Bytes(input));

export const verifySignature = (signatureHex: string, digest: Uint8Array, pubHex: string): boolean =>
  secp256k1.verify(hexToBytes(signatureHex), digest, hexToBytes(pubHex), { prehash: false });

// ---------- GG20 distributed key generation (one party) ----------

export const makeParty = async (): Promise<Party> => {
  const x = randomScalar();
  const X = scalarToPointHex(x);
  const paillier = paillierKeygen(PAILLIER_PRIME_BITS);
  const cX = paillierEncrypt(mod(x, paillier.n), paillier);
  const commitment = await sha256Hex(X);
  return { x, X, paillier, cX, commitment };
};

// ---------- GG20 threshold signing (2-of-2, faithful) ----------
//
// Produces a standard secp256k1 signature over `digest`. The full private key
// x = x₁ + x₂ and the full nonce k = k₁ + k₂ are NEVER reconstructed anywhere.
//
// Nonce inversion trick: instead of R = k·G (which would force inverting a
// shared secret), GG20 sets R = δ⁻¹·Γ where Γ = γ·G and δ = k·γ, giving
// R = (kγ)⁻¹·γ·G = k⁻¹·G. So the effective ECDSA nonce is k⁻¹ and
//     s = Σ sᵢ = Σ (e·kᵢ + r·σᵢ) = e·k + r·k·x = k·(e + r·x).
export const gg20Sign = (
  d: { p1: Party; p2: Party; jointPub: string },
  digest: Uint8Array,
  cheat = false
): SignResult => {
  const { p1, p2 } = d;

  // Round 1 — each party samples nonce shares kᵢ, γᵢ and commits Γᵢ = γᵢ·G.
  const k1 = randomScalar();
  const g1 = randomScalar();
  const k2 = randomScalar();
  const g2 = randomScalar();
  const Gamma1 = BASE.multiply(g1);
  // A cheating P2 commits to γ₂+1 but uses γ₂ in the MtA below — an inconsistency
  // GG20's consistency checks are designed to catch.
  const g2Reveal = cheat ? mod(g2 + 1n, ORDER) : g2;
  const Gamma2 = BASE.multiply(g2Reveal);

  // Round 2a — MtA over Paillier for δ = k·γ = (k₁+k₂)(γ₁+γ₂).
  //   local: k₁γ₁ (P1), k₂γ₂ (P2);  cross terms via MtA.
  const k1g2 = mta(k1, g2, p1.paillier); // P1 encrypts k₁, P2 raises to γ₂
  const k2g1 = mta(k2, g1, p2.paillier); // P2 encrypts k₂, P1 raises to γ₁
  const delta1 = mod(k1 * g1 + k1g2.alpha + k2g1.beta, ORDER);
  const delta2 = mod(k2 * g2 + k1g2.beta + k2g1.alpha, ORDER);
  const delta = mod(delta1 + delta2, ORDER);

  // Round 2b — MtA for σ = k·x = (k₁+k₂)(x₁+x₂), reusing the DKG ciphertexts
  // Enc(x₁), Enc(x₂). xᵢ is only ever touched homomorphically — never revealed.
  const x1k2 = mta(p1.x, k2, p1.paillier, p1.cX); // P2 raises P1's published Enc(x₁) to k₂
  const x2k1 = mta(p2.x, k1, p2.paillier, p2.cX); // P1 raises P2's published Enc(x₂) to k₁
  const sigma1 = mod(k1 * p1.x + x1k2.alpha + x2k1.beta, ORDER);
  const sigma2 = mod(k2 * p2.x + x1k2.beta + x2k1.alpha, ORDER);

  if (delta === 0n) throw new Error('δ = k·γ collapsed to 0 (negligible) — restart signing');

  // Round 3 — reveal δ, derive R = δ⁻¹·Γ = k⁻¹·G, then each party computes sᵢ.
  const Gamma = Gamma1.add(Gamma2);
  const R = Gamma.multiply(modInv(delta, ORDER));
  const Rhex = hex(R.toBytes(true));
  const r = pointX(Rhex);
  if (r === 0n) throw new Error('r = 0 (negligible) — restart signing');

  const e = mod(BigInt(`0x${hex(digest)}`), ORDER);
  const s1 = mod(e * k1 + r * sigma1, ORDER);
  const s2 = mod(e * k2 + r * sigma2, ORDER);
  let s = mod(s1 + s2, ORDER);
  if (s === 0n) throw new Error('s = 0 (negligible) — restart signing');
  if (s > HALF_ORDER) s = ORDER - s; // BIP-146 low-S

  const signatureHex = `${to32Hex(r)}${to32Hex(s)}`;
  const verified = verifySignature(signatureHex, digest, d.jointPub);

  const abortReason =
    !verified && cheat
      ? 'Party 2 committed Γ₂ inconsistent with the γ₂ it used in MtA. The joint R no longer equals k⁻¹·G, so the signature fails — detection is real. Real GG20 then runs a blame phase (the ZK range proof of Exhibit 6 plus the further checks of Exhibit 7) to attribute the abort to Party 2 specifically; this demo implements the keystone range proof and documents the rest.'
      : undefined;

  return {
    cheat,
    Gamma1: hex(Gamma1.toBytes(true)),
    Gamma2: hex(Gamma2.toBytes(true)),
    delta1,
    delta2,
    delta,
    sigma1,
    sigma2,
    R: Rhex,
    r,
    s1,
    s2,
    s,
    signatureHex,
    verified,
    abortReason
  };
};

// ---------- ZK range proof for MtA (real, runnable) ----------
//
// Every MtA message in GG20 carries a zero-knowledge proof that the encrypted
// value is "small" (in [0, q)). Without it, a malicious party could encrypt a
// value m ≈ N so that m·(other share) + blind WRAPS modulo n, silently
// corrupting the additive sharing and breaking the signature (or leaking key
// material). This is the proof referenced in Exhibit 5.
//
// It is the classic GG18 / Lindell range proof: a Fiat–Shamir Σ-protocol over
// the Paillier ciphertext and a Pedersen-style commitment using an auxiliary
// RSA modulus Ñ. It proves m ∈ [0, q) WITHOUT revealing m.
//
//   Statement : c = (1+N)^m · r^N mod N²   encrypts some m ∈ [0, q)
//   Witness   : m, r
//   Aux (trusted setup): Ñ = P̃·Q̃,  h₁ ∈ Z*_Ñ,  h₂ = h₁^λ  (λ discarded)
//
//   Prover:  α←[0,q³) ρ←[0,q·Ñ) γ←[0,q³·Ñ) β←Z*_N
//            z = h₁^m·h₂^ρ        (mod Ñ)
//            u = (1+N)^α·β^N      (mod N²)
//            w = h₁^α·h₂^γ        (mod Ñ)
//            e = H(N,c,z,u,w) mod q
//            s = r^e·β (mod N),  s₁ = e·m+α,  s₂ = e·ρ+γ   (s₁,s₂ over ℤ)
//
//   Verifier checks (all four must hold):
//            (1) 0 ≤ s₁ ≤ q³                       ← the RANGE bound
//            (2) e = H(N,c,z,u,w) mod q            ← Fiat–Shamir binding
//            (3) (1+N)^s₁·s^N ≡ u·c^e  (mod N²)    ← ties proof to ciphertext
//            (4) h₁^s₁·h₂^s₂ ≡ w·z^e   (mod Ñ)     ← ties proof to commitment

// Range bound: the proof shows the value is at most q³ (with honest values < q,
// so s₁ = e·m+α < q²+q³ ≤ q³ except with probability ~1/q ≈ 2⁻²⁵⁶).
export const RANGE_BOUND = ORDER * ORDER * ORDER; // q³

export type RangeProofAux = { nTilde: bigint; h1: bigint; h2: bigint };

export type RangeProof = {
  z: bigint;
  u: bigint;
  w: bigint;
  s: bigint;
  s1: bigint;
  s2: bigint;
  e: bigint;
};

// Trusted setup of the auxiliary modulus. In production this is run by the
// verifier (or a trusted dealer) so the prover never learns λ = log_{h₁}(h₂);
// soundness rests on that. Here we generate and discard λ.
export const setupRangeProofAux = (bits = PAILLIER_PRIME_BITS): RangeProofAux => {
  const nTilde = genPrime(bits) * genPrime(bits);
  let f = randBelow(nTilde);
  while (gcd(f, nTilde) !== 1n) f = randBelow(nTilde);
  const h1 = mod(f * f, nTilde); // a quadratic residue, generates a large subgroup
  const lambda = randBelow(nTilde); // discarded — prover must not know it
  const h2 = modPow(h1, lambda, nTilde);
  return { nTilde, h1, h2 };
};

const rangeChallenge = async (
  n: bigint,
  c: bigint,
  z: bigint,
  u: bigint,
  w: bigint
): Promise<bigint> => {
  const digest = await sha256Hex(
    `${n.toString(16)}|${c.toString(16)}|${z.toString(16)}|${u.toString(16)}|${w.toString(16)}`
  );
  return mod(BigInt(`0x${digest}`), ORDER);
};

export const proveRange = async (
  m: bigint,
  r: bigint,
  c: bigint,
  pk: PaillierKeyPair,
  aux: RangeProofAux
): Promise<RangeProof> => {
  const { nTilde, h1, h2 } = aux;
  const alpha = randBelow(RANGE_BOUND);
  const rho = randBelow(ORDER * nTilde);
  const gamma = randBelow(RANGE_BOUND * nTilde);
  let beta = randBelow(pk.n - 1n) + 1n;
  while (gcd(beta, pk.n) !== 1n) beta = randBelow(pk.n - 1n) + 1n;

  const z = mod(modPow(h1, m, nTilde) * modPow(h2, rho, nTilde), nTilde);
  const u = mod(modPow(pk.g, alpha, pk.nsq) * modPow(beta, pk.n, pk.nsq), pk.nsq);
  const w = mod(modPow(h1, alpha, nTilde) * modPow(h2, gamma, nTilde), nTilde);

  const e = await rangeChallenge(pk.n, c, z, u, w);
  const s = mod(modPow(r, e, pk.n) * beta, pk.n);
  const s1 = e * m + alpha; // over the integers — large s₁ reveals a large m
  const s2 = e * rho + gamma;
  return { z, u, w, s, s1, s2, e };
};

export type RangeVerdict = { ok: boolean; reason: string; rangeOk: boolean };

export const verifyRange = async (
  proof: RangeProof,
  c: bigint,
  pk: PaillierKeyPair,
  aux: RangeProofAux
): Promise<RangeVerdict> => {
  const { nTilde, h1, h2 } = aux;
  const { z, u, w, s, s1, s2, e } = proof;

  // (1) Range bound — the check that actually stops the wraparound attack.
  const rangeOk = s1 >= 0n && s1 <= RANGE_BOUND;
  if (!rangeOk) {
    return {
      ok: false,
      rangeOk: false,
      reason: `range check FAILED: s₁ has ${s1.toString(2).length} bits but the bound q³ has ${RANGE_BOUND.toString(2).length} — the encrypted value is too large (out of [0, q)).`
    };
  }
  // (2) Fiat–Shamir consistency.
  if ((await rangeChallenge(pk.n, c, z, u, w)) !== e) {
    return { ok: false, rangeOk, reason: 'challenge mismatch: the proof was tampered with.' };
  }
  // (3) Paillier relation.
  const lhs1 = mod(modPow(pk.g, s1, pk.nsq) * modPow(s, pk.n, pk.nsq), pk.nsq);
  const rhs1 = mod(u * modPow(c, e, pk.nsq), pk.nsq);
  if (lhs1 !== rhs1) {
    return { ok: false, rangeOk, reason: 'Paillier relation (1+N)^s₁·s^N ≠ u·c^e — proof invalid.' };
  }
  // (4) Commitment relation.
  const lhs2 = mod(modPow(h1, s1, nTilde) * modPow(h2, s2, nTilde), nTilde);
  const rhs2 = mod(w * modPow(z, e, nTilde), nTilde);
  if (lhs2 !== rhs2) {
    return { ok: false, rangeOk, reason: 'commitment relation h₁^s₁·h₂^s₂ ≠ w·z^e — proof invalid.' };
  }
  return {
    ok: true,
    rangeOk: true,
    reason: 'all four checks passed: the plaintext is proven to lie in [0, q) — without revealing it.'
  };
};
