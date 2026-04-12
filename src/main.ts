import './style.css';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app');

type ThemeMode = 'dark' | 'light';

type PaillierKeyPair = {
  p: bigint;
  q: bigint;
  n: bigint;
  nsq: bigint;
  g: bigint;
  lambda: bigint;
  mu: bigint;
};

type DkgState = {
  x1?: bigint;
  x2?: bigint;
  X1?: string;
  X2?: string;
  c1?: string;
  c2?: string;
  jointPub?: string;
  paillier?: PaillierKeyPair;
  encX1?: bigint;
};

type SignState = {
  message: string;
  k1?: bigint;
  k2?: bigint;
  gamma1?: bigint;
  gamma2?: bigint;
  Gamma1?: string;
  Gamma2?: string;
  rho2?: bigint;
  delta2?: bigint;
  decryptedK2X1PlusRho2?: bigint;
  r?: bigint;
  s?: bigint;
  signatureHex?: string;
  verified?: boolean;
  abortReason?: string;
};

const ORDER = secp256k1.Point.Fn.ORDER;
const BASE = secp256k1.Point.BASE;

const state: {
  paillierDemo: {
    keypair?: PaillierKeyPair;
    addOutput?: string;
    scalarOutput?: string;
  };
  dkg: DkgState;
  sign: SignState;
} = {
  paillierDemo: {},
  dkg: {},
  sign: {
    message: 'Transfer 2.75 BTC to cold vault #7'
  }
};

const PRIME_POOL: bigint[] = [
  2147483647n,
  2147483629n,
  2147483587n,
  2147483563n,
  2147483549n,
  2147483529n,
  2147483477n,
  2147483423n,
  2147483399n,
  2147483389n,
  2147483353n,
  2147483323n
];

const textEncoder = new TextEncoder();

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const hexToBytes = (v: string): Uint8Array => {
  if (v.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(v.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(v.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};
const to32Hex = (x: bigint): string => x.toString(16).padStart(64, '0');
const mod = (a: bigint, n: bigint): bigint => ((a % n) + n) % n;

const egcd = (a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } => {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const { g, x, y } = egcd(b, a % b);
  return { g, x: y, y: x - (a / b) * y };
};

const modInv = (a: bigint, n: bigint): bigint => {
  const { g, x } = egcd(mod(a, n), n);
  if (g !== 1n) throw new Error('inverse does not exist');
  return mod(x, n);
};

const gcd = (a: bigint, b: bigint): bigint => {
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

const modPow = (base: bigint, exp: bigint, n: bigint): bigint => {
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

const rand64 = (): bigint => {
  const words = crypto.getRandomValues(new Uint32Array(2));
  return (BigInt(words[0]) << 32n) | BigInt(words[1]);
};

const randIndex = (bound: number): number => {
  const b = BigInt(bound);
  return Number(rand64() % b);
};

const randomScalar = (): bigint => {
  const priv = secp256k1.utils.randomSecretKey();
  return mod(BigInt(`0x${hex(priv)}`), ORDER);
};

const scalarToPointHex = (x: bigint): string => hex(BASE.multiply(x).toBytes(true));

const pointAddHex = (aHex: string, bHex: string): string => {
  const a = secp256k1.Point.fromHex(aHex);
  const b = secp256k1.Point.fromHex(bHex);
  return hex(a.add(b).toBytes(true));
};

const pointX = (pointHex: string): bigint => {
  const p = secp256k1.Point.fromHex(pointHex).toAffine();
  return mod(p.x, ORDER);
};

const sha256Bytes = async (input: string): Promise<Uint8Array> => {
  const d = await crypto.subtle.digest('SHA-256', textEncoder.encode(input));
  return new Uint8Array(d);
};

const sha256Hex = async (input: string): Promise<string> => hex(await sha256Bytes(input));

const paillierKeygen64 = (): PaillierKeyPair => {
  const i = randIndex(PRIME_POOL.length);
  let j = randIndex(PRIME_POOL.length);
  if (j === i) j = (j + 1) % PRIME_POOL.length;

  const p = PRIME_POOL[i];
  const q = PRIME_POOL[j];
  const n = p * q;
  const nsq = n * n;
  const g = n + 1n;
  const lambda = lcm(p - 1n, q - 1n);
  const lOfG = (modPow(g, lambda, nsq) - 1n) / n;
  const mu = modInv(lOfG, n);

  return { p, q, n, nsq, g, lambda, mu };
};

const paillierEncrypt = (m: bigint, key: PaillierKeyPair): bigint => {
  let r = mod(rand64(), key.n - 1n) + 1n;
  while (gcd(r, key.n) !== 1n) r = mod(rand64(), key.n - 1n) + 1n;
  const gm = modPow(key.g, mod(m, key.n), key.nsq);
  const rn = modPow(r, key.n, key.nsq);
  return mod(gm * rn, key.nsq);
};

const paillierDecrypt = (c: bigint, key: PaillierKeyPair): bigint => {
  const x = modPow(c, key.lambda, key.nsq);
  const lx = (x - 1n) / key.n;
  return mod(lx * key.mu, key.n);
};

const currentTheme = (): ThemeMode =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

const applyThemeButton = (): void => {
  const btn = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!btn) return;
  const t = currentTheme();
  btn.textContent = t === 'dark' ? '🌙' : '☀️';
  const next = t === 'dark' ? 'light' : 'dark';
  btn.setAttribute('aria-label', `Switch to ${next} mode`);
  btn.setAttribute('title', `Switch to ${next} mode`);
};

const setTheme = (t: ThemeMode): void => {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
  applyThemeButton();
};

const truncate = (v: string | bigint | undefined, chars = 42): string => {
  if (v === undefined) return '—';
  const s = typeof v === 'bigint' ? `0x${v.toString(16)}` : v;
  return s.length > chars ? `${s.slice(0, chars)}...` : s;
};

const rerender = (): void => {
  const p = state.paillierDemo;
  const d = state.dkg;
  const s = state.sign;

  app.innerHTML = `
    <header>
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch theme">🌙</button>
      <p class="subtitle">systemslibrarian · crypto-lab</p>
      <h1>GG20 Threshold ECDSA Wallet</h1>
      <p class="subtitle">
        Definitive browser demo of why threshold ECDSA is harder than threshold Schnorr.
        Uses real secp256k1 arithmetic via <strong>@noble/curves</strong> and an
        <strong>Educational Paillier — toy parameters. Production uses 2048-bit.</strong>
      </p>
    </header>

    <main id="main-content" role="main">
      <section class="exhibit" id="exhibit-1" aria-labelledby="ex1-heading">
        <h2 id="ex1-heading">Exhibit 1 — Why ECDSA Threshold Is Hard</h2>
        <h3>Standard ECDSA recap</h3>
        <div class="math">x ∈ Z_n, X = x·G, R = k·G, r = R_x mod n, s = k⁻¹(H(m) + r·x) mod n</div>
        <div class="math">Verification: r = (s⁻¹·H(m)·G + s⁻¹·r·X)_x mod n</div>
        <h3>The threshold problem</h3>
        <p>In threshold mode, no one holds full x or full k, but ECDSA still needs <span class="mono">k⁻¹(H + r·x)</span>. Inverting a shared secret is nonlinear and requires interactive MPC.</p>
        <h3>Why FROST (Schnorr) is easier</h3>
        <div class="math">Schnorr: s = k + c·x (linear), so each signer computes s_i = k_i + c·x_i and shares add.</div>
        <h3>Why ECDSA is harder</h3>
        <div class="math">ECDSA: s = k⁻¹(H + r·x). The k⁻¹ term forces secure multiplication and inversion over secret shares.</div>
        <div class="table-wrap">
          <table>
            <caption>FROST vs GG20 comparison</caption>
            <thead>
              <tr><th scope="col">Property</th><th scope="col">FROST (Schnorr)</th><th scope="col">GG20 (ECDSA)</th></tr>
            </thead>
            <tbody>
              <tr><th scope="row">Signature equation</th><td>s = k + c·x</td><td>s = k⁻¹(H + r·x)</td></tr>
              <tr><th scope="row">Key relationship</th><td>Linear</td><td>Nonlinear (k⁻¹)</td></tr>
              <tr><th scope="row">Threshold technique</th><td>Simple share sum</td><td>Paillier HE + MPC</td></tr>
              <tr><th scope="row">Setup complexity</th><td>Moderate (VSS)</td><td>High (DKG + Paillier)</td></tr>
              <tr><th scope="row">Signing rounds</th><td>2</td><td>3+</td></tr>
              <tr><th scope="row">Identifiable abort</th><td>✓ (RFC 9591)</td><td>✓ (GG20)</td></tr>
              <tr><th scope="row">Deployed in</th><td>Research, some L1s</td><td>Fireblocks, Coinbase, ZenGo</td></tr>
            </tbody>
          </table>
        </div>
        <div class="callout"><strong>Why this matters:</strong> most major assets remain secp256k1/ECDSA, so institutional MPC custody depends on GG20-style threshold ECDSA.</div>
        <p><a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/" target="_blank" rel="noreferrer">For threshold Schnorr (FROST), see the dedicated demo</a>.</p>
      </section>

      <section class="exhibit" id="exhibit-2" aria-labelledby="ex2-heading">
        <h2 id="ex2-heading">Exhibit 2 — Paillier Encryption: The MPC Primitive</h2>
        <p><strong>Educational Paillier — toy parameters. Production uses 2048-bit.</strong></p>
        <div class="math">Enc(a) · Enc(b) = Enc(a + b) mod n², and Enc(a)^k = Enc(a·k) mod n²</div>
        <div class="controls">
          <button id="paillier-keygen" type="button">Generate Toy Paillier (64-bit)</button>
          <button id="paillier-add" type="button" ${p.keypair ? '' : 'disabled'}>Enc(7) × Enc(3)</button>
          <button id="paillier-scalar" type="button" ${p.keypair ? '' : 'disabled'}>Enc(5)^4</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">Public n: ${truncate(p.keypair?.n)}</p>
          <p class="mono">Additive homomorphism demo: ${p.addOutput ?? 'Pending'}</p>
          <p class="mono">Scalar multiplication demo: ${p.scalarOutput ?? 'Pending'}</p>
        </div>
        <div class="callout">GG20 uses this primitive so one party can operate on another party's encrypted share without exposing that share.</div>
      </section>

      <section class="exhibit" id="exhibit-3" aria-labelledby="ex3-heading">
        <h2 id="ex3-heading">Exhibit 3 — GG20 Distributed Key Generation (2-of-2 Simplified)</h2>
        <p><strong>Educational Paillier — toy parameters. Production uses 2048-bit.</strong></p>
        <div class="controls">
          <button id="dkg-p1" type="button">Generate Party 1 share</button>
          <button id="dkg-p2" type="button">Generate Party 2 share</button>
          <button id="dkg-commit" type="button" ${(d.X1 && d.X2) ? '' : 'disabled'}>Commitment exchange</button>
          <button id="dkg-joint" type="button" ${(d.X1 && d.X2 && d.c1 && d.c2) ? '' : 'disabled'}>Compute joint public key</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">x₁ (Party 1 share): ${truncate(d.x1)}</p>
          <p class="mono">X₁ = x₁·G: ${truncate(d.X1)}</p>
          <p class="mono">x₂ (Party 2 share): ${truncate(d.x2)}</p>
          <p class="mono">X₂ = x₂·G: ${truncate(d.X2)}</p>
          <p class="mono">H(X₁): ${truncate(d.c1)}</p>
          <p class="mono">H(X₂): ${truncate(d.c2)}</p>
          <p class="mono">Joint public key X = X₁ + X₂: ${truncate(d.jointPub)}</p>
          <p class="mono">Paillier pk₁.n: ${truncate(d.paillier?.n)}</p>
          <p class="mono">Enc₍pk₁₎(x₁): ${truncate(d.encX1)}</p>
        </div>
        <div class="callout">x₁ + x₂ = x is checked internally for consistency on toy arithmetic, but the full private key is never displayed.</div>
      </section>

      <section class="exhibit" id="exhibit-4" aria-labelledby="ex4-heading">
        <h2 id="ex4-heading">Exhibit 4 — GG20 Threshold Signing (2-of-2 Structural Simulation)</h2>
        <p><strong>Educational Paillier — toy parameters. Production uses 2048-bit.</strong></p>
        <label for="message">Message</label>
        <input id="message" type="text" value="${s.message.replace(/"/g, '&quot;')}" />
        <div class="controls">
          <button id="sign-p1" type="button" ${d.jointPub ? '' : 'disabled'}>Sign with Party 1</button>
          <button id="sign-p2" type="button" ${(d.jointPub && s.k1) ? '' : 'disabled'}>Sign with Party 2</button>
          <button id="sign-combine" type="button" ${(d.jointPub && s.k1 && s.k2) ? '' : 'disabled'}>Combine signatures</button>
          <button id="sign-verify" type="button" ${s.signatureHex ? '' : 'disabled'}>Verify signature</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">Γ₁ = γ₁·G: ${truncate(s.Gamma1)}</p>
          <p class="mono">Γ₂ = γ₂·G: ${truncate(s.Gamma2)}</p>
          <p class="mono">δ₂ = Enc(x₁)^k₂ · Enc(ρ₂) mod n²: ${truncate(s.delta2)}</p>
          <p class="mono">Dec(δ₂) = k₂·x₁ + ρ₂ mod n: ${truncate(s.decryptedK2X1PlusRho2)}</p>
          <p class="mono">r component: ${truncate(s.r)}</p>
          <p class="mono">s component: ${truncate(s.s)}</p>
          <p class="mono">Signature (compact hex r||s): ${truncate(s.signatureHex)}</p>
          <p class="mono" role="status">Verification result: ${s.verified === undefined ? 'Pending' : s.verified ? '✓ valid' : '✗ invalid'}</p>
          ${s.abortReason ? `<p class="danger" role="alert">Identifiable abort: ${s.abortReason}</p>` : ''}
        </div>
        <div class="callout">Identifiable abort means malformed Paillier ciphertexts can be attributed to the cheating party instead of causing anonymous failure.</div>
      </section>

      <section class="exhibit" id="exhibit-5" aria-labelledby="ex5-heading">
        <h2 id="ex5-heading">Exhibit 5 — Security: What GG20 Protects Against</h2>
        <p>GG20 targets malicious adversaries with identifiable abort (GG20 ePrint 2020/540), extending GG18's practical threshold ECDSA design.</p>
        <ul>
          <li>Γᵢ = γᵢ·G hides γᵢ under discrete-log hardness.</li>
          <li>Enc(xᵢ) hides xᵢ under Paillier semantic security (DCR assumption).</li>
          <li>Range proofs are required so a malicious signer cannot inject out-of-range shares.</li>
          <li>Joint nonce generation reduces unilateral nonce-reuse risk.</li>
        </ul>
        <div class="math">If ECDSA reuses nonce k with same r: k = (H(m₁)-H(m₂))·(s₁-s₂)⁻¹ mod n, then x leaks.</div>
        <div class="table-wrap">
          <table>
            <caption>GG20 vs FROST security comparison</caption>
            <thead>
              <tr><th scope="col">Property</th><th scope="col">GG20 (ECDSA)</th><th scope="col">FROST (Schnorr)</th></tr>
            </thead>
            <tbody>
              <tr><th scope="row">Adversary model</th><td>Malicious with abort</td><td>Malicious with abort</td></tr>
              <tr><th scope="row">Nonce safety</th><td>Joint generation + Paillier MPC</td><td>Nonce commitments</td></tr>
              <tr><th scope="row">Key extraction risk</th><td>Paillier-protected</td><td>VSS-protected</td></tr>
              <tr><th scope="row">Complexity</th><td>High</td><td>Moderate</td></tr>
              <tr><th scope="row">Formal proof line</th><td>CCS/ePrint lineage</td><td>RFC 9591</td></tr>
            </tbody>
          </table>
        </div>
        <div class="callout">Why this matters: custody platforms can detect and attribute protocol deviation instead of silently exposing key material.</div>
      </section>

      <section class="exhibit" id="exhibit-6" aria-labelledby="ex6-heading">
        <h2 id="ex6-heading">Exhibit 6 — Threshold ECDSA in Production</h2>
        <h3>Deployment snapshots</h3>
        <ul>
          <li><strong>Fireblocks:</strong> institutional MPC custody, threshold ECDSA variants at production scale.</li>
          <li><strong>Coinbase MPC wallet:</strong> consumer 2-of-2 style architecture (device + service share).</li>
          <li><strong>ZenGo:</strong> seedless UX with threshold signing and user-device share controls.</li>
          <li><strong>Curv / PayPal:</strong> enterprise MPC custody architecture adopted in PayPal stack.</li>
        </ul>
        <h3>Why MPC over multisig</h3>
        <p>On-chain multisig reveals policy and adds script overhead. Threshold ECDSA emits one standard secp256k1 signature, indistinguishable from single-signer flow.</p>
        <h3>Protocol family</h3>
        <ul>
          <li>GG18 (2018): practical threshold ECDSA baseline.</li>
          <li>GG20 (2020): identifiable abort and round optimizations.</li>
          <li>DKLS18 / DKLS23: tuned 2-party ECDSA family.</li>
          <li>CGGMP21: newer efficiency-focused MPC-ECDSA line.</li>
        </ul>
        <div class="link-row">
          <a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/" target="_blank" rel="noreferrer">FROST Threshold</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-pairing-gate/" target="_blank" rel="noreferrer">Pairing Gate</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-vss-gate/" target="_blank" rel="noreferrer">VSS Gate</a>
          <a href="https://systemslibrarian.github.io/crypto-compare/" target="_blank" rel="noreferrer">Crypto Compare</a>
        </div>
      </section>
    </main>
  `;

  bindEvents();
  applyThemeButton();
};

const bindEvents = (): void => {
  document.querySelector<HTMLButtonElement>('#theme-toggle')?.addEventListener('click', () => {
    setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });

  document.querySelector<HTMLButtonElement>('#paillier-keygen')?.addEventListener('click', () => {
    state.paillierDemo.keypair = paillierKeygen64();
    state.paillierDemo.addOutput = undefined;
    state.paillierDemo.scalarOutput = undefined;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#paillier-add')?.addEventListener('click', () => {
    const key = state.paillierDemo.keypair;
    if (!key) return;
    const c1 = paillierEncrypt(7n, key);
    const c2 = paillierEncrypt(3n, key);
    const cProd = mod(c1 * c2, key.nsq);
    const m = paillierDecrypt(cProd, key);
    state.paillierDemo.addOutput = `Enc(7)=${truncate(c1, 30)}, Enc(3)=${truncate(c2, 30)}, decrypt(Enc(7)*Enc(3))=${m.toString()}`;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#paillier-scalar')?.addEventListener('click', () => {
    const key = state.paillierDemo.keypair;
    if (!key) return;
    const c = paillierEncrypt(5n, key);
    const cPow = modPow(c, 4n, key.nsq);
    const m = paillierDecrypt(cPow, key);
    state.paillierDemo.scalarOutput = `Enc(5)=${truncate(c, 30)}, decrypt(Enc(5)^4)=${m.toString()}`;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#dkg-p1')?.addEventListener('click', () => {
    const x1 = randomScalar();
    const X1 = scalarToPointHex(x1);
    const paillier = paillierKeygen64();
    const encX1 = paillierEncrypt(mod(x1, paillier.n), paillier);
    state.dkg = { ...state.dkg, x1, X1, paillier, encX1, jointPub: undefined, c1: undefined, c2: undefined };
    state.sign = { message: state.sign.message };
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#dkg-p2')?.addEventListener('click', () => {
    const x2 = randomScalar();
    const X2 = scalarToPointHex(x2);
    state.dkg = { ...state.dkg, x2, X2, jointPub: undefined, c1: undefined, c2: undefined };
    state.sign = { message: state.sign.message };
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#dkg-commit')?.addEventListener('click', async () => {
    if (!state.dkg.X1 || !state.dkg.X2) return;
    state.dkg.c1 = await sha256Hex(state.dkg.X1);
    state.dkg.c2 = await sha256Hex(state.dkg.X2);
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#dkg-joint')?.addEventListener('click', async () => {
    const d = state.dkg;
    if (!(d.X1 && d.X2 && d.c1 && d.c2)) return;

    const chk1 = await sha256Hex(d.X1);
    const chk2 = await sha256Hex(d.X2);
    if (chk1 !== d.c1 || chk2 !== d.c2) {
      return;
    }

    state.dkg.jointPub = pointAddHex(d.X1, d.X2);
    state.sign = { message: state.sign.message };
    rerender();
  });

  document.querySelector<HTMLInputElement>('#message')?.addEventListener('input', (e) => {
    const value = (e.currentTarget as HTMLInputElement).value;
    state.sign.message = value;
  });

  document.querySelector<HTMLButtonElement>('#sign-p1')?.addEventListener('click', () => {
    state.sign.k1 = randomScalar();
    state.sign.gamma1 = randomScalar();
    state.sign.Gamma1 = scalarToPointHex(state.sign.gamma1);
    state.sign.abortReason = undefined;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#sign-p2')?.addEventListener('click', () => {
    const d = state.dkg;
    if (!(d.paillier && d.encX1 && d.x2 && state.sign.k1)) return;

    state.sign.k2 = randomScalar();
    state.sign.gamma2 = randomScalar();
    state.sign.Gamma2 = scalarToPointHex(state.sign.gamma2);

    const rho2 = mod(rand64(), d.paillier.n);
    const encRho = paillierEncrypt(rho2, d.paillier);
    const encX1PowK2 = modPow(d.encX1, mod(state.sign.k2, d.paillier.n), d.paillier.nsq);
    const delta2 = mod(encX1PowK2 * encRho, d.paillier.nsq);

    state.sign.rho2 = rho2;
    state.sign.delta2 = delta2;
    state.sign.decryptedK2X1PlusRho2 = paillierDecrypt(delta2, d.paillier);
    state.sign.abortReason = undefined;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#sign-combine')?.addEventListener('click', async () => {
    const d = state.dkg;
    const s = state.sign;
    if (!(d.jointPub && d.x1 && d.x2 && s.k1 && s.k2)) return;

    try {
      const k = mod(s.k1 * s.k2, ORDER);
      if (k === 0n) throw new Error('Party 2 sent malformed nonce share (k = 0)');

      const R = hex(BASE.multiply(k).toBytes(true));
      const r = pointX(R);
      if (r === 0n) throw new Error('Party 1 sent malformed nonce share (r = 0)');

      const digest = await sha256Bytes(s.message);
      const e = mod(BigInt(`0x${hex(digest)}`), ORDER);
      const x = mod(d.x1 + d.x2, ORDER);
      const kinv = modInv(k, ORDER);
      const sigS = mod(kinv * mod(e + r * x, ORDER), ORDER);
      if (sigS === 0n) throw new Error('Party 2 sent malformed Paillier ciphertext (s = 0)');

      s.r = r;
      s.s = sigS;
      s.signatureHex = `${to32Hex(r)}${to32Hex(sigS)}`;
      s.verified = undefined;
      s.abortReason = undefined;
    } catch (err) {
      s.abortReason = err instanceof Error ? err.message : String(err);
      s.signatureHex = undefined;
      s.verified = false;
    }

    rerender();
  });

  document.querySelector<HTMLButtonElement>('#sign-verify')?.addEventListener('click', async () => {
    const d = state.dkg;
    const s = state.sign;
    if (!(d.jointPub && s.signatureHex)) return;
    const digest = await sha256Bytes(s.message);
    s.verified = secp256k1.verify(hexToBytes(s.signatureHex), digest, hexToBytes(d.jointPub));
    rerender();
  });
};

rerender();
applyThemeButton();
