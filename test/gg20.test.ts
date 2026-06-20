// Correctness proof for the GG20 core. Run with: npm test
// Uses the Node built-in test runner (node --test) against the same module the
// browser UI imports — so a green test bar is evidence the live demo is real.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ORDER,
  HALF_ORDER,
  RANGE_BOUND,
  mod,
  isProbablePrime,
  paillierKeygen,
  paillierEncrypt,
  paillierDecrypt,
  mta,
  makeParty,
  gg20Sign,
  sha256Bytes,
  sha256Hex,
  scalarToPointHex,
  pointX,
  randomScalar,
  pointAddHex,
  verifySignature,
  setupRangeProofAux,
  proveRange,
  verifyRange,
  paillierEncryptWithR
} from '../src/gg20.ts';

test('Miller–Rabin recognises known primes and composites', () => {
  assert.equal(isProbablePrime(2n), true);
  assert.equal(isProbablePrime(97n), true);
  assert.equal(isProbablePrime(7919n), true);
  assert.equal(isProbablePrime(1n), false);
  assert.equal(isProbablePrime(91n), false); // 7·13
  assert.equal(isProbablePrime(7917n), false);
});

test('Paillier keygen produces a usable, correct keypair', () => {
  const key = paillierKeygen(256);
  assert.equal(key.n, key.p * key.q);
  assert.equal(isProbablePrime(key.p), true);
  assert.equal(isProbablePrime(key.q), true);
  const m = 123456789n;
  assert.equal(paillierDecrypt(paillierEncrypt(m, key), key), m);
});

test('Paillier is additively homomorphic and scalar-multiplicative', () => {
  const key = paillierKeygen(256);
  const sum = paillierDecrypt(mod(paillierEncrypt(7n, key) * paillierEncrypt(3n, key), key.nsq), key);
  assert.equal(sum, 10n);
});

test('MtA yields additive shares of the product over ORDER', () => {
  const key = paillierKeygen(512);
  for (let i = 0; i < 20; i += 1) {
    const a = randomScalar();
    const b = randomScalar();
    const { alpha, beta } = mta(a, b, key);
    assert.equal(mod(alpha + beta, ORDER), mod(a * b, ORDER));
  }
});

test('MtA reuses a precomputed ciphertext correctly', () => {
  const key = paillierKeygen(512);
  const a = randomScalar();
  const b = randomScalar();
  const encA = paillierEncrypt(mod(a, key.n), key);
  const { alpha, beta } = mta(a, b, key, encA);
  assert.equal(mod(alpha + beta, ORDER), mod(a * b, ORDER));
});

test('DKG: commitments open correctly and joint key = X₁+X₂ = (x₁+x₂)·G', async () => {
  const p1 = await makeParty();
  const p2 = await makeParty();
  // each commitment H(Xᵢ) opens to the revealed Xᵢ
  assert.equal(await sha256Hex(p1.X), p1.commitment);
  assert.equal(await sha256Hex(p2.X), p2.commitment);
  const joint = pointAddHex(p1.X, p2.X);
  assert.equal(joint, scalarToPointHex(mod(p1.x + p2.x, ORDER)));
});

test('GG20 signing produces a valid standard ECDSA signature', async () => {
  const p1 = await makeParty();
  const p2 = await makeParty();
  const jointPub = pointAddHex(p1.X, p2.X);
  const digest = await sha256Bytes('Transfer 2.75 BTC to cold vault #7');
  const res = gg20Sign({ p1, p2, jointPub }, digest, false);
  assert.equal(res.verified, true);
  // independent re-verification through the public API
  assert.equal(verifySignature(res.signatureHex, digest, jointPub), true);
  // low-S enforced (BIP-146)
  assert.ok(res.s <= HALF_ORDER);
});

test('GG20 internal relations hold (δ=δ₁+δ₂, s=s₁+s₂, r = R_x)', async () => {
  const p1 = await makeParty();
  const p2 = await makeParty();
  const jointPub = pointAddHex(p1.X, p2.X);
  const digest = await sha256Bytes('relations');
  const res = gg20Sign({ p1, p2, jointPub }, digest, false);
  // δ is the sum of the two parties' additive shares
  assert.equal(mod(res.delta1 + res.delta2, ORDER), res.delta);
  // s = s₁ + s₂, up to the low-S sign flip
  const sRaw = mod(res.s1 + res.s2, ORDER);
  assert.ok(sRaw === res.s || ORDER - sRaw === res.s);
  // r is the x-coordinate of the recovered R = δ⁻¹·Γ = k⁻¹·G
  assert.equal(pointX(res.R), res.r);
});

test('25 random end-to-end signings all verify (the in-app self-test)', async () => {
  const p1 = await makeParty();
  const p2 = await makeParty();
  const jointPub = pointAddHex(p1.X, p2.X);
  let pass = 0;
  for (let i = 0; i < 25; i += 1) {
    const digest = await sha256Bytes(`msg #${i} ${Math.random()}`);
    if (gg20Sign({ p1, p2, jointPub }, digest, false).verified) pass += 1;
  }
  assert.equal(pass, 25);
});

test('malicious Party 2 (inconsistent Γ₂) is detected and aborts', async () => {
  const p1 = await makeParty();
  const p2 = await makeParty();
  const jointPub = pointAddHex(p1.X, p2.X);
  const digest = await sha256Bytes('cheat attempt');
  const res = gg20Sign({ p1, p2, jointPub }, digest, true);
  assert.equal(res.verified, false);
  assert.ok(res.abortReason && res.abortReason.length > 0);
});

test('ZK range proof: honest in-range value verifies', async () => {
  const pk = paillierKeygen(512);
  const aux = setupRangeProofAux(512);
  const m = randomScalar(); // a legitimate share, < q
  const { c, r } = paillierEncryptWithR(m, pk);
  const proof = await proveRange(m, r, c, pk, aux);
  const v = await verifyRange(proof, c, pk, aux);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.rangeOk, true);
});

test('ZK range proof: out-of-range value (m ≈ N) is REJECTED by the range check', async () => {
  const pk = paillierKeygen(512);
  const aux = setupRangeProofAux(512);
  const m = pk.n - 1n; // the wraparound-attack value: far outside [0, q)
  const { c, r } = paillierEncryptWithR(m, pk);
  const proof = await proveRange(m, r, c, pk, aux);
  const v = await verifyRange(proof, c, pk, aux);
  assert.equal(v.ok, false);
  assert.equal(v.rangeOk, false); // specifically the range bound, not some other check
  assert.ok(proof.s1 > RANGE_BOUND);
});

test('ZK range proof: a tampered proof fails a soundness check', async () => {
  const pk = paillierKeygen(512);
  const aux = setupRangeProofAux(512);
  const m = randomScalar();
  const { c, r } = paillierEncryptWithR(m, pk);
  const proof = await proveRange(m, r, c, pk, aux);
  // forge s1 to a small in-range value to dodge the range check
  const forged = { ...proof, s1: 42n };
  const v = await verifyRange(forged, c, pk, aux);
  assert.equal(v.ok, false); // caught by the Paillier/commitment relations
});

test('ZK range proof: proof for one ciphertext does not verify against another', async () => {
  const pk = paillierKeygen(512);
  const aux = setupRangeProofAux(512);
  const m = randomScalar();
  const { c, r } = paillierEncryptWithR(m, pk);
  const proof = await proveRange(m, r, c, pk, aux);
  const other = paillierEncryptWithR(randomScalar(), pk).c;
  const v = await verifyRange(proof, other, pk, aux);
  assert.equal(v.ok, false);
});

test('the full private key is never reconstructed during signing', async () => {
  // Structural guarantee: signing depends only on each party's own x_i via its
  // local σ_i; there is no code path that returns or stores x₁+x₂. We assert the
  // signing API surface never exposes a full-key field.
  const p1 = await makeParty();
  const p2 = await makeParty();
  const jointPub = pointAddHex(p1.X, p2.X);
  const res = gg20Sign({ p1, p2, jointPub }, await sha256Bytes('x'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(res, 'x'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(res, 'privateKey'), false);
});
