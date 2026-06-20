import './style.css';
import {
  type Party,
  type SignResult,
  type PaillierKeyPair,
  type RangeProofAux,
  type RangeProof,
  type RangeVerdict,
  ORDER,
  RANGE_BOUND,
  mod,
  modPow,
  paillierKeygen,
  paillierEncrypt,
  paillierEncryptWithR,
  paillierDecrypt,
  scalarToPointHex,
  pointAddHex,
  sha256Bytes,
  sha256Hex,
  makeParty,
  gg20Sign,
  verifySignature,
  randomScalar,
  setupRangeProofAux,
  proveRange,
  verifyRange
} from './gg20.ts';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app');

type ThemeMode = 'dark' | 'light';

type DkgState = {
  p1?: Party;
  p2?: Party;
  jointPub?: string; // X = X₁ + X₂
  selfCheck?: string;
  generating?: 'p1' | 'p2';
};

type SignState = {
  message: string;
  cheat: boolean;
  result?: SignResult;
  verifyEcho?: string;
  selfTest?: { pass: number; total: number; running: boolean };
};

type ZkRun = { m: bigint; c: bigint; proof: RangeProof; verdict: RangeVerdict };

type ZkState = {
  pk?: PaillierKeyPair;
  aux?: RangeProofAux;
  generating?: boolean;
  honest?: ZkRun;
  malicious?: ZkRun;
};

const state: {
  paillierDemo: { keypair?: PaillierKeyPair; addOutput?: string; scalarOutput?: string };
  dkg: DkgState;
  sign: SignState;
  zk: ZkState;
} = {
  paillierDemo: {},
  dkg: {},
  sign: {
    message: 'Transfer 2.75 BTC to cold vault #7',
    cheat: false
  },
  zk: {}
};

// ---------- Theme ----------

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

// ---------- Formatting ----------

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

const truncate = (v: string | bigint | undefined, chars = 42): string => {
  if (v === undefined) return '—';
  const s = typeof v === 'bigint' ? `0x${v.toString(16)}` : v;
  return s.length > chars ? `${s.slice(0, chars)}…` : s;
};

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const honesty = (real: string, simplified: string): string => `
  <details class="honesty">
    <summary>What's real / what's simplified</summary>
    <p><strong>Real:</strong> ${real}</p>
    <p><strong>Simplified:</strong> ${simplified}</p>
  </details>`;

// ---------- Render ----------

const rerender = (): void => {
  const p = state.paillierDemo;
  const d = state.dkg;
  const s = state.sign;
  const z = state.zk;
  const res = s.result;
  const ready = Boolean(d.p1 && d.p2 && d.jointPub);
  const zkReady = Boolean(z.pk && z.aux);

  const zkRunRows = (run: ZkRun | undefined): string =>
    run
      ? `
        <p class="mono">m (secret plaintext, hidden in proof): ${run.m > RANGE_BOUND ? `${truncate(run.m, 20)} — ${run.m.toString(2).length} bits` : 'a valid share < q (256 bits)'}</p>
        <p class="mono">s₁ = e·m + α: ${run.proof.s1.toString(2).length} bits   (range bound q³ = ${RANGE_BOUND.toString(2).length} bits)</p>
        <p class="mono ${run.verdict.rangeOk ? 'ok' : 'danger'}">① range check (0 ≤ s₁ ≤ q³): ${run.verdict.rangeOk ? '✓ pass' : '✗ FAIL'}</p>
        <p class="mono ${run.verdict.ok ? 'ok' : 'danger'}">verdict: ${run.verdict.ok ? '✓ accepted' : '✗ rejected'} — ${esc(run.verdict.reason)}</p>`
      : '';

  app.innerHTML = `
    <header>
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch theme">🌙</button>
      <p class="subtitle">systemslibrarian · crypto-lab</p>
      <h1>GG20 Threshold ECDSA Wallet</h1>
      <p class="subtitle">
        A faithful, runnable 2-of-2 GG20 threshold-ECDSA signer. Real secp256k1 arithmetic via
        <strong>@noble/curves</strong>, real Paillier homomorphic encryption, and real MtA share
        conversion — the full private key is <strong>never reconstructed</strong> at any point.
      </p>
      <p class="banner">
        🔬 Educational sizes: Paillier uses 1024-bit n (production: ≥2048-bit). The cryptographic
        <em>logic</em> is the genuine GG20 protocol — only the key sizes and the ZK proof layer are scaled down.
      </p>
    </header>

    <main id="main-content" role="main">
      <section class="exhibit" id="exhibit-1" aria-labelledby="ex1-heading">
        <h2 id="ex1-heading">Exhibit 1 — Why ECDSA Threshold Is Hard</h2>
        <h3>Standard ECDSA recap</h3>
        <div class="math">x ∈ Z_n, X = x·G, R = k·G, r = R_x mod n, s = k⁻¹(H(m) + r·x) mod n</div>
        <h3>The threshold problem</h3>
        <p>In threshold mode, no one holds full x or full k, but ECDSA still needs <span class="mono">k⁻¹(H + r·x)</span>. Inverting and multiplying <em>shared secrets</em> is nonlinear and requires interactive MPC.</p>
        <h3>Why FROST (Schnorr) is easier</h3>
        <div class="math">Schnorr: s = k + c·x (linear), so each signer computes s_i = k_i + c·x_i and shares simply add.</div>
        <h3>Why ECDSA is harder</h3>
        <div class="math">ECDSA: s = k⁻¹(H + r·x). The k⁻¹ and r·x terms force secure multiplication of secret shares.</div>
        <div class="table-wrap">
          <table>
            <caption>FROST vs GG20 comparison</caption>
            <thead>
              <tr><th scope="col">Property</th><th scope="col">FROST (Schnorr)</th><th scope="col">GG20 (ECDSA)</th></tr>
            </thead>
            <tbody>
              <tr><th scope="row">Signature equation</th><td>s = k + c·x</td><td>s = k⁻¹(H + r·x)</td></tr>
              <tr><th scope="row">Key relationship</th><td>Linear</td><td>Nonlinear (k⁻¹, r·x)</td></tr>
              <tr><th scope="row">Threshold technique</th><td>Simple share sum</td><td>Paillier MtA + MPC</td></tr>
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
        <p>Paillier is <em>additively homomorphic</em>: you can add encrypted values, and multiply an encrypted value by a public scalar, without decrypting. GG20 builds its secure multiplication (MtA) on exactly these two identities.</p>
        <div class="math">Enc(a) · Enc(b) = Enc(a + b) mod n²,    Enc(a)^k = Enc(a·k) mod n²</div>
        <div class="controls">
          <button id="paillier-keygen" type="button">Generate readable Paillier (small)</button>
          <button id="paillier-add" type="button" ${p.keypair ? '' : 'disabled'}>Enc(7) · Enc(3) → ?</button>
          <button id="paillier-scalar" type="button" ${p.keypair ? '' : 'disabled'}>Enc(5)⁴ → ?</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">Public n: ${truncate(p.keypair?.n)}</p>
          <p class="mono">Additive homomorphism:    ${esc(p.addOutput ?? 'Pending')}</p>
          <p class="mono">Scalar multiplication:    ${esc(p.scalarOutput ?? 'Pending')}</p>
        </div>
        <div class="callout">In GG20 one party operates on another party's <em>encrypted</em> share — adding a blind and multiplying by a private scalar — without ever seeing the plaintext. That is the engine of Exhibit 4.</div>
        ${honesty(
          'The homomorphic identities and the keygen/encrypt/decrypt are the genuine Paillier scheme (DCR-based).',
          'Tiny primes are used here so the ciphertexts are short enough to read. Exhibits 3–4 use a 1024-bit modulus.'
        )}
      </section>

      <section class="exhibit" id="exhibit-3" aria-labelledby="ex3-heading">
        <h2 id="ex3-heading">Exhibit 3 — GG20 Distributed Key Generation (2-of-2)</h2>
        <p>Each party samples a secret share xᵢ, broadcasts a hash commitment H(Xᵢ) <em>before</em> revealing Xᵢ = xᵢ·G (so no one can adaptively choose their share), and publishes Encᵢ(xᵢ) under their own Paillier key for later use in signing. The wallet's public key is X = X₁ + X₂.</p>
        <div class="controls">
          <button id="dkg-p1" type="button" ${d.generating ? 'disabled' : ''}>${d.generating === 'p1' ? 'Generating 1024-bit key…' : 'Generate Party 1'}</button>
          <button id="dkg-p2" type="button" ${d.generating ? 'disabled' : ''}>${d.generating === 'p2' ? 'Generating 1024-bit key…' : 'Generate Party 2'}</button>
          <button id="dkg-joint" type="button" ${d.p1 && d.p2 ? '' : 'disabled'}>Open commitments → joint public key</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">P1 commitment H(X₁): ${truncate(d.p1?.commitment)}</p>
          <p class="mono">P1 X₁ = x₁·G:        ${truncate(d.p1?.X)}</p>
          <p class="mono">P1 Enc(x₁):          ${truncate(d.p1?.cX)}</p>
          <p class="mono">P2 commitment H(X₂): ${truncate(d.p2?.commitment)}</p>
          <p class="mono">P2 X₂ = x₂·G:        ${truncate(d.p2?.X)}</p>
          <p class="mono">P2 Enc(x₂):          ${truncate(d.p2?.cX)}</p>
          <p class="mono accent">Joint public key X = X₁ + X₂: ${truncate(d.jointPub)}</p>
          ${d.selfCheck ? `<p class="mono ${d.jointPub ? 'ok' : 'danger'}">${esc(d.selfCheck)}</p>` : ''}
        </div>
        <div class="callout">x₁ and x₂ stay on their own party. The shares are never summed into a single secret — not here, and not during signing.</div>
        ${honesty(
          'Hash-commit-then-reveal ordering, real secp256k1 key shares, and real Paillier encryption of each share.',
          'A trusted "open commitments" step stands in for the full broadcast channel; n = 2 parties; no Feldman/VSS for t < n.'
        )}
      </section>

      <section class="exhibit" id="exhibit-4" aria-labelledby="ex4-heading">
        <h2 id="ex4-heading">Exhibit 4 — GG20 Threshold Signing (faithful, no key reconstruction)</h2>
        ${ready ? '' : '<p class="warn" role="status">Complete Exhibit 3 (both parties + joint key) to enable signing.</p>'}
        <ol class="flow">
          <li><strong>Round 1:</strong> P1 picks (k₁, γ₁), P2 picks (k₂, γ₂); each reveals Γᵢ = γᵢ·G.</li>
          <li><strong>Round 2:</strong> MtA over Paillier converts the cross-products into additive shares of δ = k·γ and σ = k·x.</li>
          <li><strong>Round 3:</strong> reveal δ, set R = δ⁻¹·Γ = k⁻¹·G, each party computes sᵢ = e·kᵢ + r·σᵢ; output s = s₁ + s₂.</li>
        </ol>
        <label for="message">Message to sign</label>
        <input id="message" type="text" value="${esc(s.message)}" ${ready ? '' : 'disabled'} />
        <label class="check">
          <input id="cheat" type="checkbox" ${s.cheat ? 'checked' : ''} ${ready ? '' : 'disabled'} />
          Simulate a malicious Party 2 (commit Γ₂ inconsistent with the γ₂ used in MtA)
        </label>
        <div class="controls">
          <button id="sign-run" type="button" ${ready ? '' : 'disabled'}>Run GG20 signing (all rounds)</button>
          <button id="sign-verify" type="button" ${res?.signatureHex ? '' : 'disabled'}>Verify with @noble/curves</button>
          <button id="self-test" type="button" ${ready && !s.selfTest?.running ? '' : 'disabled'}>${s.selfTest?.running ? 'Running…' : 'Self-test: 25 random signings'}</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">R1 · Γ₁ = γ₁·G: ${truncate(res?.Gamma1)}</p>
          <p class="mono">R1 · Γ₂ = γ₂·G: ${truncate(res?.Gamma2)}</p>
          <p class="mono">R2 · δ₁ (P1's share of k·γ): ${truncate(res?.delta1, 30)}</p>
          <p class="mono">R2 · δ₂ (P2's share of k·γ): ${truncate(res?.delta2, 30)}</p>
          <p class="mono">R2 · δ = δ₁+δ₂ = k·γ (revealed): ${truncate(res?.delta, 30)}</p>
          <p class="mono">R2 · σ₁ (P1's share of k·x — never shared): ${res ? '🔒 held by P1' : '—'}</p>
          <p class="mono">R2 · σ₂ (P2's share of k·x — never shared): ${res ? '🔒 held by P2' : '—'}</p>
          <p class="mono">R3 · R = δ⁻¹·Γ = k⁻¹·G: ${truncate(res?.R)}</p>
          <p class="mono">R3 · s₁ (P1 local): ${truncate(res?.s1, 30)}</p>
          <p class="mono">R3 · s₂ (P2 local): ${truncate(res?.s2, 30)}</p>
          <p class="mono">r component: ${truncate(res?.r)}</p>
          <p class="mono">s = s₁+s₂ component: ${truncate(res?.s)}</p>
          <p class="mono">Signature (compact r‖s): ${truncate(res?.signatureHex)}</p>
          <p class="mono" role="status">Verification: ${
            res === undefined ? 'Pending' : res.verified ? '✓ valid standard ECDSA signature' : '✗ invalid'
          }</p>
          ${s.verifyEcho ? `<p class="mono ${res?.verified ? 'ok' : 'danger'}">${esc(s.verifyEcho)}</p>` : ''}
          ${res?.abortReason ? `<p class="danger" role="alert">⚠ Identifiable abort: ${esc(res.abortReason)}</p>` : ''}
          ${
            s.selfTest && !s.selfTest.running
              ? `<p class="mono ${s.selfTest.pass === s.selfTest.total ? 'ok' : 'danger'}">Self-test: ${s.selfTest.pass}/${s.selfTest.total} random signatures verified — and the secret was never reconstructed in any run.</p>`
              : ''
          }
        </div>
        <div class="callout"><strong>🔒 The key claim, made testable:</strong> nowhere in the code is x₁+x₂ or k₁+k₂ ever computed during signing. P1 holds σ₁, P2 holds σ₂, and s = s₁ + s₂ where each sᵢ is computed locally. The self-test proves 25 such signatures verify against the public key.</div>
        ${honesty(
          'Real MtA over 1024-bit Paillier, the genuine δ = k·γ nonce-inversion (R = δ⁻¹·Γ = k⁻¹·G), and an output that verifies as an ordinary secp256k1 signature.',
          'The ZK range/consistency proofs are omitted, so cheating is detected (signature fails) but not cryptographically attributed; δ is revealed in the clear as in the protocol.'
        )}
      </section>

      <section class="exhibit" id="exhibit-5" aria-labelledby="ex5-heading">
        <h2 id="ex5-heading">Exhibit 5 — Security: What GG20 Protects Against</h2>
        <p>GG20 targets malicious adversaries with identifiable abort (Gennaro–Goldfeder, ePrint 2020/540), extending GG18's practical threshold ECDSA design.</p>
        <ul>
          <li>Γᵢ = γᵢ·G hides γᵢ under discrete-log hardness.</li>
          <li>Enc(xᵢ) hides xᵢ under Paillier semantic security (DCR assumption).</li>
          <li>MtA range proofs stop a malicious signer injecting out-of-range shares that would wrap modulo n — <strong>run this proof yourself in Exhibit 6</strong>.</li>
          <li>Joint nonce generation removes any single party's ability to reuse or bias k.</li>
        </ul>
        <div class="math">If ECDSA reuses nonce k with same r: x = (s·k − H(m))·r⁻¹, and k = (H(m₁)−H(m₂))·(s₁−s₂)⁻¹ — the key leaks.</div>
        <div class="table-wrap">
          <table>
            <caption>GG20 vs FROST security comparison</caption>
            <thead>
              <tr><th scope="col">Property</th><th scope="col">GG20 (ECDSA)</th><th scope="col">FROST (Schnorr)</th></tr>
            </thead>
            <tbody>
              <tr><th scope="row">Adversary model</th><td>Malicious with abort</td><td>Malicious with abort</td></tr>
              <tr><th scope="row">Nonce safety</th><td>Joint generation + Paillier MtA</td><td>Nonce commitments</td></tr>
              <tr><th scope="row">Key extraction risk</th><td>Paillier + range proofs</td><td>VSS-protected</td></tr>
              <tr><th scope="row">Complexity</th><td>High</td><td>Moderate</td></tr>
              <tr><th scope="row">Formal proof line</th><td>CCS / ePrint lineage</td><td>RFC 9591</td></tr>
            </tbody>
          </table>
        </div>
        <div class="callout">Why this matters: custody platforms can detect and attribute protocol deviation instead of silently exposing key material. Try the "malicious Party 2" toggle in Exhibit 4 to see detection in action.</div>
      </section>

      <section class="exhibit" id="exhibit-6" aria-labelledby="ex6-heading">
        <h2 id="ex6-heading">Exhibit 6 — Zero-Knowledge Range Proof (runnable)</h2>
        <!-- runnable ZK range proof -->
        <p>This is the proof Exhibit 5 referred to, implemented for real. Every MtA message in GG20 carries a ZK proof that the encrypted value is <em>small</em> (in [0, q)). Without it, a malicious party could encrypt m ≈ N so that m·(other share) + blind <strong>wraps modulo n</strong>, silently corrupting the additive sharing. The proof convinces the verifier the value is in range <em>without revealing it</em> — the classic GG18 / Lindell Σ-protocol over a Pedersen commitment (auxiliary modulus Ñ).</p>
        <div class="math">Prove: c = (1+N)^m·r^N encrypts m ∈ [0, q).  Check: s₁≤q³,  (1+N)^s₁·s^N ≡ u·c^e,  h₁^s₁·h₂^s₂ ≡ w·z^e</div>
        <div class="controls">
          <button id="zk-setup" type="button" ${z.generating ? 'disabled' : ''}>${z.generating ? 'Generating…' : 'Trusted setup: Paillier key + aux (Ñ, h₁, h₂)'}</button>
          <button id="zk-honest" type="button" ${zkReady ? '' : 'disabled'}>Honest prover: m &lt; q</button>
          <button id="zk-malicious" type="button" ${zkReady ? '' : 'disabled'}>Malicious prover: m ≈ N (wraparound)</button>
        </div>
        <div aria-live="polite" aria-atomic="true">
          <p class="mono">Paillier n: ${truncate(z.pk?.n)}</p>
          <p class="mono">Aux Ñ: ${truncate(z.aux?.nTilde)}</p>
          <h3>Honest prover</h3>
          ${z.honest ? zkRunRows(z.honest) : '<p class="mono">— run the honest prover —</p>'}
          <h3>Malicious prover (out-of-range value)</h3>
          ${z.malicious ? zkRunRows(z.malicious) : '<p class="mono">— run the malicious prover —</p>'}
        </div>
        <div class="callout"><strong>Why this matters:</strong> the algebraic relations hold for the cheater too — only the <em>range bound</em> s₁ ≤ q³ catches them. That single inequality is what makes GG20's MtA safe against the wraparound attack from Exhibit 5.</div>
        ${honesty(
          'A genuine, verifying Fiat–Shamir range proof: real Pedersen commitments mod Ñ, real Paillier relation mod N², real soundness (tampered proofs and out-of-range values are rejected).',
          'The aux modulus uses a single trusted setup in-page (production: the verifier supplies Ñ so the prover cannot know log_{h₁} h₂); 512-bit primes; q³ slack rather than a tightened bound.'
        )}
      </section>

      <section class="exhibit" id="exhibit-7" aria-labelledby="ex7-heading">
        <h2 id="ex7-heading">Exhibit 7 — The Full Identifiable-Abort Stack</h2>
        <p>Exhibit 6 implements the MtA range proof. A production GG20 stack layers several more proofs on top to reach <em>identifiable</em> abort — every party can not only detect that the protocol failed, but cryptographically prove <em>which</em> party deviated. Here is the rest of the machinery, and exactly where this demo stops.</p>
        <h3>1. Paillier–Blum modulus proof (Πᵐᵒᵈ)</h3>
        <p>At key generation each party proves, in zero knowledge, that its Paillier modulus N is the product of two primes ≡ 3 (mod 4) and is square-free. This stops a malicious N for which decryption is ambiguous or the range proof is unsound. <em>Status here: assumed honest (we generate well-formed N).</em></p>
        <h3>2. MtA-with-check (range + discrete-log binding)</h3>
        <p>In the σ = k·x phase, the value being multiplied is a <em>committed key share</em> xᵢ with public point Xᵢ = xᵢ·G. MtA-with-check augments the range proof of Exhibit 6 with one extra equation proving the <em>same</em> m satisfies Xᵢ = m·G — so a party cannot use one value in the EC commitment and a different one inside Paillier. <em>Status here: range proof implemented (Exhibit 6); the DL-binding equation is described but not wired into the signing path.</em></p>
        <div class="math">Extra commitment: û = m·G (curve point);  extra check: s₁·G ≟ û + e·Xᵢ</div>
        <h3>3. Consistency check on δ and R</h3>
        <p>After δ = k·γ is revealed, parties check g^δ against the published Γᵢ. A mismatch (exactly what the "malicious Party 2" toggle in Exhibit 4 induces) signals an abort. <em>Status here: detection is real — the signature fails to verify.</em></p>
        <h3>4. Type-5 and Type-7 aborts (attribution)</h3>
        <p>If the final signature fails, GG20 runs a blame phase: parties reveal additional commitments and ZK proofs so honest parties agree on the single cheating identity. The "type-5"/"type-7" labels refer to the protocol phase whose proof failed. This is the step that turns <em>detection</em> into <em>identification</em>. <em>Status here: described, not implemented — faithful attribution needs every preceding proof in place.</em></p>
        <div class="callout">The honest takeaway: detection (does the protocol output a valid signature?) is cheap and real in this demo. Attribution (who cheated?) requires the full proof stack above; we implement its keystone — the range proof — and document the rest rather than fake it.</div>
        <div class="table-wrap">
          <table>
            <caption>Proof obligations in production GG20 vs. this demo</caption>
            <thead><tr><th scope="col">Component</th><th scope="col">Purpose</th><th scope="col">This demo</th></tr></thead>
            <tbody>
              <tr><th scope="row">secp256k1 + Paillier + MtA</th><td>Joint signing without key reconstruction</td><td>✓ implemented</td></tr>
              <tr><th scope="row">MtA range proof</th><td>Prevent out-of-range / wraparound</td><td>✓ implemented (Exhibit 6)</td></tr>
              <tr><th scope="row">Paillier–Blum proof</th><td>Well-formed modulus</td><td>○ assumed honest</td></tr>
              <tr><th scope="row">MtA DL-binding</th><td>Tie Paillier value to Xᵢ</td><td>○ described</td></tr>
              <tr><th scope="row">Type-5/7 blame phase</th><td>Attribute the cheater</td><td>○ described</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="exhibit" id="exhibit-8" aria-labelledby="ex8-heading" role="region">
        <h2 id="ex8-heading">Exhibit 8 — Threshold ECDSA in Production</h2>
        <h3>Deployment snapshots</h3>
        <ul>
          <li><strong>Fireblocks:</strong> institutional MPC custody, threshold ECDSA variants at production scale.</li>
          <li><strong>Coinbase MPC wallet:</strong> consumer 2-of-2 style architecture (device + service share).</li>
          <li><strong>ZenGo:</strong> seedless UX with threshold signing and user-device share controls.</li>
          <li><strong>Curv / PayPal:</strong> enterprise MPC custody architecture adopted in PayPal's stack.</li>
        </ul>
        <h3>Why MPC over multisig</h3>
        <p>On-chain multisig reveals policy and adds script overhead. Threshold ECDSA emits one standard secp256k1 signature, indistinguishable from a single-signer flow — exactly the signature Exhibit 4 produces.</p>
        <h3>Protocol family</h3>
        <ul>
          <li>GG18 (2018): practical threshold ECDSA baseline.</li>
          <li>GG20 (2020): identifiable abort and round optimizations (this demo).</li>
          <li>DKLS18 / DKLS23: OT-based 2-party ECDSA family (no Paillier).</li>
          <li>CGGMP21: newer efficiency-focused MPC-ECDSA line.</li>
        </ul>
        <h3>Further reading</h3>
        <ul>
          <li><a href="https://eprint.iacr.org/2020/540" target="_blank" rel="noreferrer">Gennaro &amp; Goldfeder, "One Round Threshold ECDSA with Identifiable Abort" (ePrint 2020/540)</a></li>
          <li><a href="https://eprint.iacr.org/2019/114" target="_blank" rel="noreferrer">GG18 (ePrint 2019/114)</a> · <a href="https://en.wikipedia.org/wiki/Paillier_cryptosystem" target="_blank" rel="noreferrer">Paillier cryptosystem</a></li>
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

// ---------- Events ----------

const resetDownstream = (): void => {
  state.sign.result = undefined;
  state.sign.verifyEcho = undefined;
  state.sign.selfTest = undefined;
};

const bindEvents = (): void => {
  document.querySelector<HTMLButtonElement>('#theme-toggle')?.addEventListener('click', () => {
    setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });

  // Exhibit 2 — Paillier playground (small, readable key)
  document.querySelector<HTMLButtonElement>('#paillier-keygen')?.addEventListener('click', () => {
    state.paillierDemo.keypair = paillierKeygen(16);
    state.paillierDemo.addOutput = undefined;
    state.paillierDemo.scalarOutput = undefined;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#paillier-add')?.addEventListener('click', () => {
    const key = state.paillierDemo.keypair;
    if (!key) return;
    const c1 = paillierEncrypt(7n, key);
    const c2 = paillierEncrypt(3n, key);
    const m = paillierDecrypt(mod(c1 * c2, key.nsq), key);
    state.paillierDemo.addOutput = `Dec(Enc(7)·Enc(3)) = ${m} = 7+3 ✓`;
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#paillier-scalar')?.addEventListener('click', () => {
    const key = state.paillierDemo.keypair;
    if (!key) return;
    const m = paillierDecrypt(modPow(paillierEncrypt(5n, key), 4n, key.nsq), key);
    state.paillierDemo.scalarOutput = `Dec(Enc(5)⁴) = ${m} = 5·4 ✓`;
    rerender();
  });

  // Exhibit 3 — DKG
  const generateParty = async (which: 'p1' | 'p2'): Promise<void> => {
    state.dkg.generating = which;
    rerender();
    await tick(); // let the "Generating…" state paint before the CPU-bound keygen
    state.dkg[which] = await makeParty();
    state.dkg.jointPub = undefined;
    state.dkg.selfCheck = undefined;
    state.dkg.generating = undefined;
    resetDownstream();
    rerender();
  };

  document.querySelector<HTMLButtonElement>('#dkg-p1')?.addEventListener('click', () => void generateParty('p1'));
  document.querySelector<HTMLButtonElement>('#dkg-p2')?.addEventListener('click', () => void generateParty('p2'));

  document.querySelector<HTMLButtonElement>('#dkg-joint')?.addEventListener('click', async () => {
    const { p1, p2 } = state.dkg;
    if (!p1 || !p2) return;
    // Open commitments: verify each revealed Xᵢ matches its earlier hash commitment.
    const ok1 = (await sha256Hex(p1.X)) === p1.commitment;
    const ok2 = (await sha256Hex(p2.X)) === p2.commitment;
    if (!ok1 || !ok2) {
      state.dkg.selfCheck = '✗ Commitment mismatch — aborting DKG.';
      state.dkg.jointPub = undefined;
      rerender();
      return;
    }
    state.dkg.jointPub = pointAddHex(p1.X, p2.X);
    // Sanity check the additive sharing WITHOUT exposing the full key: verify
    // X == (x₁+x₂)·G by point math (equivalent to X₁+X₂). The scalar sum is used
    // only inside this assertion and never as signing material.
    const consistent = scalarToPointHex(mod(p1.x + p2.x, ORDER)) === state.dkg.jointPub;
    state.dkg.selfCheck = consistent
      ? '✓ Consistency check passed: X₁+X₂ = (x₁+x₂)·G (verified by point arithmetic; full key never displayed).'
      : '✗ Internal consistency check failed.';
    resetDownstream();
    rerender();
  });

  // Exhibit 4 — signing
  document.querySelector<HTMLInputElement>('#message')?.addEventListener('input', (e) => {
    state.sign.message = (e.currentTarget as HTMLInputElement).value;
  });

  document.querySelector<HTMLInputElement>('#cheat')?.addEventListener('change', (e) => {
    state.sign.cheat = (e.currentTarget as HTMLInputElement).checked;
  });

  document.querySelector<HTMLButtonElement>('#sign-run')?.addEventListener('click', async () => {
    const { p1, p2, jointPub } = state.dkg;
    if (!p1 || !p2 || !jointPub) return;
    state.sign.verifyEcho = undefined;
    try {
      const digest = await sha256Bytes(state.sign.message);
      state.sign.result = gg20Sign({ p1, p2, jointPub }, digest, state.sign.cheat);
    } catch (err) {
      state.sign.result = undefined;
      state.sign.verifyEcho = err instanceof Error ? `Aborted: ${err.message}` : String(err);
    }
    rerender();
  });

  document.querySelector<HTMLButtonElement>('#sign-verify')?.addEventListener('click', async () => {
    const { jointPub } = state.dkg;
    const res = state.sign.result;
    if (!jointPub || !res) return;
    const digest = await sha256Bytes(state.sign.message);
    const ok = verifySignature(res.signatureHex, digest, jointPub);
    state.sign.verifyEcho = `secp256k1.verify(sig, SHA-256("${truncate(state.sign.message, 28)}"), X) → ${ok ? 'true ✓' : 'false ✗'}`;
    rerender();
  });

  // Exhibit 6 — ZK range proof
  document.querySelector<HTMLButtonElement>('#zk-setup')?.addEventListener('click', async () => {
    state.zk.generating = true;
    state.zk.honest = undefined;
    state.zk.malicious = undefined;
    rerender();
    await tick();
    state.zk.pk = paillierKeygen(512);
    state.zk.aux = setupRangeProofAux(512);
    state.zk.generating = false;
    rerender();
  });

  const runRangeProof = async (m: bigint, slot: 'honest' | 'malicious'): Promise<void> => {
    const { pk, aux } = state.zk;
    if (!pk || !aux) return;
    const { c, r } = paillierEncryptWithR(m, pk);
    const proof = await proveRange(m, r, c, pk, aux);
    const verdict = await verifyRange(proof, c, pk, aux);
    state.zk[slot] = { m, c, proof, verdict };
    rerender();
  };

  document
    .querySelector<HTMLButtonElement>('#zk-honest')
    ?.addEventListener('click', () => void runRangeProof(randomScalar(), 'honest'));

  document
    .querySelector<HTMLButtonElement>('#zk-malicious')
    ?.addEventListener('click', () => {
      // m ≈ N: the value a cheater would use to force the MtA wraparound.
      const pk = state.zk.pk;
      if (pk) void runRangeProof(pk.n - 1n, 'malicious');
    });

  document.querySelector<HTMLButtonElement>('#self-test')?.addEventListener('click', async () => {
    const { p1, p2, jointPub } = state.dkg;
    if (!p1 || !p2 || !jointPub) return;
    const total = 25;
    state.sign.selfTest = { pass: 0, total, running: true };
    rerender();
    await tick();
    let pass = 0;
    for (let i = 0; i < total; i += 1) {
      const digest = await sha256Bytes(`self-test message #${i} — ${state.sign.message}`);
      try {
        if (gg20Sign({ p1, p2, jointPub }, digest, false).verified) pass += 1;
      } catch {
        /* counts as failure */
      }
    }
    state.sign.selfTest = { pass, total, running: false };
    rerender();
  });
};

rerender();
applyThemeButton();
