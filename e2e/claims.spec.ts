import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate: the claims this page makes, asserted against the rendered
 * page rather than against the source.
 *
 * The a11y suite proves the page is usable; this proves it is *right*. Every
 * headline verdict here is cross-checked against something the page itself
 * computed (Σkᵢ·R against the real generator, Σσᵢ·R against the joint public
 * key the DKG panel printed, r against R's x-coordinate, α+β against a·b), or
 * against the arithmetic the page displays alongside it — never against a
 * string the page could print while the math underneath was wrong.
 *
 * Every failure path the UI exposes is exercised: the malicious-Party-2 toggle
 * (Phase-5 abort), the out-of-range prover (range-bound rejection), the
 * pre-DKG gating, and re-verifying a signature against an edited message.
 */

// secp256k1 ground truth. The page must arrive at these by computation.
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
// q³, the range-proof fence. 256-bit q ⇒ a 768-bit bound.
const RANGE_BOUND_BITS = (ORDER * ORDER * ORDER).toString(2).length;

test.beforeEach(async ({ page }, testInfo) => {
  // Real 1024-bit Paillier keygen, real MtA, 25-signature self-test: generous
  // per-test budget rather than weakened assertions.
  testInfo.setTimeout(180_000);
  await page.goto('.');
});

// ---------- helpers ----------

/** Strip the UI's truncation ellipsis. */
const clip = (s: string): string => s.replace(/…/g, '').trim();

const bigAt = (text: string, re: RegExp): bigint => {
  const m = text.match(re);
  expect(m, `expected ${re} in: ${text}`).not.toBeNull();
  return BigInt((m as RegExpMatchArray)[1]);
};

/** A party-diagram cell's value, looked up by its exact label. */
const pdValue = (page: Page, label: string): Locator =>
  page.locator('.party-diagram .pd-cell').filter({ hasText: label }).locator('.pd-val');

/** Run Exhibit 3 end to end so signing is enabled. */
async function buildWallet(page: Page): Promise<void> {
  await page.locator('#dkg-p1').click();
  await expect(page.locator('#dkg-p1')).toBeEnabled({ timeout: 120_000 });
  await page.locator('#dkg-p2').click();
  await expect(page.locator('#dkg-joint')).toBeEnabled({ timeout: 120_000 });
  await page.locator('#dkg-joint').click();
  await expect(page.locator('#exhibit-3 [aria-live] p.mono.ok')).toContainText(
    'Consistency check passed'
  );
  await expect(page.locator('#sign-run')).toBeEnabled();
}

/** Click "Run GG20 signing" and wait for the verdict to leave its pending state. */
async function runSigning(page: Page): Promise<void> {
  await page.locator('.verify-line').waitFor();
  await page.locator('#sign-run').click();
  await expect(page.locator('.verify-line')).not.toContainText('Pending', { timeout: 120_000 });
  await expect(page.locator('.p5-verdict')).not.toContainText('Pending');
}

/** Run the trusted setup in Exhibit 6. */
async function zkSetup(page: Page): Promise<void> {
  await page.locator('#zk-setup').click();
  await expect(page.locator('#zk-honest')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#zk-malicious')).toBeEnabled();
}

/**
 * One line of a range-proof report. `slot` 0 = honest block, 1 = malicious
 * block (they render in that order inside the same live region).
 */
const zkLine = (page: Page, needle: string, slot: 0 | 1): Locator =>
  page.locator('#exhibit-6 [aria-live] p.mono').filter({ hasText: needle }).nth(slot);

// ---------- Exhibit 2: Paillier homomorphism ----------

test('Exhibit 2 computes the two homomorphic identities, not just their labels', async ({
  page,
}) => {
  await expect(page.locator('#paillier-add')).toBeDisabled();
  await expect(page.locator('#paillier-scalar')).toBeDisabled();

  await page.locator('#paillier-keygen').click();
  const live = page.locator('#exhibit-2 [aria-live]');
  await expect(live).toContainText(/Public n: 0x[0-9a-f]+/);
  await expect(page.locator('#paillier-add')).toBeEnabled();

  await page.locator('#paillier-add').click();
  await page.locator('#paillier-scalar').click();
  const text = await live.innerText();

  // Enc(a)·Enc(b) = Enc(a+b): the decryption the page printed must equal 7+3.
  expect(bigAt(text, /Dec\(Enc\(7\)·Enc\(3\)\) = (\d+)/)).toBe(10n);
  // Enc(a)^k = Enc(a·k): the decryption must equal 5·4.
  expect(bigAt(text, /Dec\(Enc\(5\)⁴\) = (\d+)/)).toBe(20n);
});

// ---------- Exhibit 3: DKG ----------

test('Exhibit 3 gates signing until commitments are opened, then publishes X = X₁ + X₂', async ({
  page,
}) => {
  await expect(page.locator('#exhibit-4 .warn')).toContainText(
    'Complete Exhibit 3 (both parties + joint key) to enable signing'
  );
  await expect(page.locator('#sign-run')).toBeDisabled();
  await expect(page.locator('#message')).toBeDisabled();
  await expect(page.locator('#cheat')).toBeDisabled();
  await expect(page.locator('#sign-verify')).toBeDisabled();
  await expect(page.locator('#self-test')).toBeDisabled();
  await expect(page.locator('#dkg-joint')).toBeDisabled();
  await expect(page.locator('#exhibit-3 [aria-live] p.accent')).toContainText(
    'Joint public key X = X₁ + X₂: —'
  );

  await page.locator('#dkg-p1').click();
  await expect(page.locator('#dkg-p1')).toBeEnabled({ timeout: 120_000 });
  await page.locator('#dkg-p2').click();
  await expect(page.locator('#dkg-joint')).toBeEnabled({ timeout: 120_000 });
  // Both parties exist but nothing has been opened yet: still no wallet key.
  await expect(page.locator('#exhibit-3 [aria-live] p.accent')).toContainText('X₁ + X₂: —');
  await expect(page.locator('#sign-run')).toBeDisabled();

  await page.locator('#dkg-joint').click();
  const live = page.locator('#exhibit-3 [aria-live]');
  const text = await live.innerText();
  const shareX = (label: string): string =>
    clip((text.match(new RegExp(`${label} = x[₁₂]·G:\\s*(\\S+)`)) as RegExpMatchArray)[1]);
  const jointHex = clip(
    (text.match(/Joint public key X = X₁ \+ X₂: (\S+)/) as RegExpMatchArray)[1]
  );

  // Two independent shares, and a joint key that is neither of them.
  expect(shareX('P1 X₁')).toMatch(/^0[23][0-9a-f]+$/);
  expect(shareX('P2 X₂')).toMatch(/^0[23][0-9a-f]+$/);
  expect(shareX('P1 X₁')).not.toBe(shareX('P2 X₂'));
  expect(jointHex).toMatch(/^0[23][0-9a-f]+$/);
  expect(jointHex).not.toBe(shareX('P1 X₁'));
  expect(jointHex).not.toBe(shareX('P2 X₂'));

  // Both parties committed before revealing: a 256-bit hash, not the point.
  expect(clip((text.match(/P1 commitment H\(X₁\): (\S+)/) as RegExpMatchArray)[1])).toMatch(
    /^[0-9a-f]{40,}$/
  );
  await expect(live.locator('p.mono.ok')).toContainText(
    'X₁+X₂ = (x₁+x₂)·G (verified by point arithmetic; full key never displayed)'
  );
  await expect(page.locator('#sign-run')).toBeEnabled();
});

// ---------- Exhibit 4: the MtA step-through ----------

test('the MtA step-through reveals a real conversion whose shares sum back to a·b', async ({
  page,
}) => {
  await expect(page.locator('#mta-next')).toBeDisabled();
  await expect(page.locator('#mta-reset')).toBeDisabled();
  await expect(page.locator('.mta-caption')).toContainText('Press Load an MtA example');

  await page.locator('#mta-run').click();
  const diagram = page.locator('.mta-diagram');
  await expect(diagram).toHaveAttribute('aria-label', /step 1 of 5/);
  // Nothing is revealed before its step: no blind, no shares, no reveal line.
  await expect(page.locator('.mta-box.blind')).toHaveCount(0);
  await expect(page.locator('.mta-box.share')).toHaveCount(0);
  await expect(page.locator('.mta-reveal')).toHaveCount(0);

  await page.locator('#mta-next').click(); // 2: Enc(a) crosses the channel
  await expect(diagram).toContainText('Enc(a) = 0x');
  await page.locator('#mta-next').click(); // 3: P2 blinds under encryption
  await expect(page.locator('.mta-box.blind')).toHaveCount(1);
  await page.locator('#mta-next').click(); // 4: both shares exist
  await expect(page.locator('.mta-box.share')).toHaveCount(2);
  await expect(page.locator('.mta-reveal')).toHaveCount(0);
  await page.locator('#mta-next').click(); // 5: the reveal

  const a = bigAt(await page.locator('.mta-col.p1 .mta-box.secret').innerText(), /a = (\d+)/);
  const b = bigAt(await page.locator('.mta-col.p2 .mta-box.secret').innerText(), /b = (\d+)/);
  const blind = bigAt(await page.locator('.mta-box.blind').innerText(), /β′ = (\d+)/);
  const alpha = bigAt(await page.locator('.mta-col.p1 .mta-box.share').innerText(), /α = (\d+)/);
  const beta = bigAt(await page.locator('.mta-col.p2 .mta-box.share').innerText(), /β′ = (\d+)/);
  const reveal = await page.locator('.mta-reveal').innerText();
  const sum = bigAt(reveal, /α \+ β = (\d+)/);
  const product = bigAt(reveal, /a·b = (\d+)/);

  // Every number on the diagram is a real MtA intermediate, so they must
  // satisfy the protocol's own relations exactly:
  expect(alpha).toBe(a * b + blind); //   α = a·b + β′  (over the integers)
  expect(beta).toBe((ORDER - blind) % ORDER); //  β = −β′  (mod q)
  expect(sum).toBe((alpha + beta) % ORDER); //  the printed sum is the real sum
  expect(product).toBe((a * b) % ORDER); //     and the printed product is real
  expect(sum).toBe(product); //                 which is the whole claim of MtA
  expect(a).toBeGreaterThan(0n);
  expect(b).toBeGreaterThan(0n);
  await expect(page.locator('.mta-reveal')).toHaveClass(/ok/);
  await expect(page.locator('.mta-reveal')).toContainText(
    'additive shares reconstruct the product'
  );
  await expect(page.locator('#mta-next')).toBeDisabled(); // step 5 is the last

  await page.locator('#mta-reset').click();
  await expect(page.locator('.mta-reveal')).toHaveCount(0);
  await expect(page.locator('.mta-box.secret')).toHaveCount(0);
});

// ---------- Exhibit 4: honest signing ----------

test('an honest run passes Phase 5 against the real G and the wallet key it printed', async ({
  page,
}) => {
  await buildWallet(page);
  const jointHex = clip(
    ((await page.locator('#exhibit-3 [aria-live] p.accent').innerText()).match(
      /X₁ \+ X₂: (\S+)/
    ) as RegExpMatchArray)[1]
  );

  await expect(page.locator('.p5-verdict')).toContainText('Pending — run signing above');
  await runSigning(page);

  const rows = page.locator('.p5-row');
  await expect(rows).toHaveCount(2);
  const kR = clip(await rows.nth(0).locator('.p5-got').innerText());
  const sigmaR = clip(await rows.nth(1).locator('.p5-got').innerText());

  // 5A: Σ kᵢ·R must be the actual secp256k1 generator — compared against the
  // curve constant, not against whatever the page felt like printing.
  expect(kR.length).toBeGreaterThan(20);
  expect(G_COMPRESSED.startsWith(kR)).toBe(true);
  // 5C: Σ σᵢ·R must be the wallet public key Exhibit 3 published. Both sides of
  // this comparison are values the page computed, in different exhibits.
  expect(sigmaR.length).toBeGreaterThan(20);
  expect(jointHex.startsWith(sigmaR)).toBe(true);

  await expect(rows.nth(0)).toContainText('Σ kᵢ·R');
  await expect(rows.nth(0)).toContainText('✓ holds');
  await expect(rows.nth(0)).toHaveClass(/ok/);
  await expect(rows.nth(1)).toContainText('Σ σᵢ·R');
  await expect(rows.nth(1)).toContainText('✓ holds');
  await expect(rows.nth(1)).toHaveClass(/ok/);
  await expect(page.locator('.p5-verdict')).toContainText(
    '✓ both identities hold — the protocol proceeds to release s₁ and s₂'
  );
  await expect(page.locator('.p5-verdict')).toHaveClass(/ok/);

  // The headline verdict, and no abort banner anywhere.
  await expect(page.locator('.verify-line')).toContainText('✓ valid standard ECDSA signature');
  await expect(page.locator('[role="alert"]')).toHaveCount(0);

  // An independent re-verification path, run by the page against @noble/curves.
  await page.locator('#sign-verify').click();
  const echo = page.locator('#exhibit-4 [aria-live] p.mono').filter({ hasText: 'secp256k1.verify' });
  await expect(echo).toContainText('→ true ✓');
  await expect(echo).toHaveClass(/ok/);
});

test('the signature the party diagram outputs is stitched from the values above it', async ({
  page,
}) => {
  await buildWallet(page);
  await runSigning(page);

  const rHex = clip(await pdValue(page, 'R = δ⁻¹·Γ = k⁻¹·G').innerText());
  const rScalar = clip(await pdValue(page, 'r = R_x mod q').innerText());
  const signature = clip(await pdValue(page, 'signature r‖s').innerText());

  expect(rHex).toMatch(/^0[23][0-9a-f]{20}$/); // compressed point, 22 chars shown
  expect(rScalar).toMatch(/^0x[0-9a-f]+$/);
  expect(signature).toMatch(/^[0-9a-f]{40}$/);

  // r is R's x-coordinate: the scalar the page printed must be the x-coordinate
  // of the point the page printed, and the signature must open with it.
  const xDigits = rHex.slice(2); // drop the 02/03 parity byte
  expect(signature.startsWith(xDigits)).toBe(true); // r‖s is zero-padded r first
  expect(rScalar.slice(2, 18)).toBe(xDigits.replace(/^0+/, '').slice(0, 16));

  // The two σ shares stay put. This is the page's central claim, and it is made
  // in the party columns — never in the broadcast lane.
  await expect(pdValue(page, '🔒 σ₁ (share of k·x)')).toHaveText('held by P1 — never sent');
  await expect(pdValue(page, '🔒 σ₂ (share of k·x)')).toHaveText('held by P2 — never sent');
  await expect(
    page.locator('.party-diagram .pd-cell').filter({ hasText: '🔒 σ₁ (share of k·x)' })
  ).toHaveClass(/pd-p1/);
  await expect(
    page.locator('.party-diagram .pd-cell').filter({ hasText: '🔒 σ₂ (share of k·x)' })
  ).toHaveClass(/pd-p2/);
  await expect(
    page.locator('.party-diagram .pd-cell').filter({ hasText: '— never broadcast —' })
  ).toContainText('σ is the secret; only its shares exist');
});

test('the 25-signature self-test reports a whole that equals the sum of its parts', async ({
  page,
}) => {
  await buildWallet(page);
  await page.locator('#self-test').click();
  const line = page.locator('#exhibit-4 [aria-live] p.mono').filter({ hasText: 'Self-test:' });
  await expect(line).toBeVisible({ timeout: 150_000 });

  const text = await line.innerText();
  const pass = Number(bigAt(text, /Self-test: (\d+)\/\d+/));
  const total = Number(bigAt(text, /Self-test: \d+\/(\d+)/));
  expect(total).toBe(25); // the count the card, README and callout all promise
  expect(pass).toBe(total); // every one verified — no silent partial credit
  await expect(line).toHaveClass(/ok/);
  await expect(line).toContainText('random signatures verified');
  await expect(page.locator('#self-test')).toBeEnabled();
});

// ---------- Exhibit 4: the malicious-Party-2 failure path ----------

test('malicious Party 2 aborts in Phase 5, says why, and the verdict follows the math', async ({
  page,
}) => {
  await buildWallet(page);
  await page.locator('#cheat').check();
  await runSigning(page);

  const rows = page.locator('.p5-row');
  const kR = clip(await rows.nth(0).locator('.p5-got').innerText());
  const sigmaR = clip(await rows.nth(1).locator('.p5-got').innerText());
  const jointHex = clip(
    ((await page.locator('#exhibit-3 [aria-live] p.accent').innerText()).match(
      /X₁ \+ X₂: (\S+)/
    ) as RegExpMatchArray)[1]
  );

  // The identities are genuinely broken — the points computed on this run are
  // not G and not X. The banner is not merely echoing the toggle.
  expect(G_COMPRESSED.startsWith(kR)).toBe(false);
  expect(jointHex.startsWith(sigmaR)).toBe(false);

  for (const i of [0, 1]) {
    await expect(rows.nth(i)).toContainText('✗ FAILS');
    await expect(rows.nth(i)).toHaveClass(/danger/);
  }
  await expect(page.locator('.p5-verdict')).toContainText(
    '✗ abort: the deviation is caught here, before any sᵢ is released'
  );
  await expect(page.locator('.p5-verdict')).toHaveClass(/danger/);

  // It says *why*, in the protocol's own terms, and is honest about its limit.
  const alert = page.locator('[role="alert"]');
  await expect(alert).toHaveCount(1);
  await expect(alert).toContainText('Identifiable abort');
  await expect(alert).toContainText('Σ kᵢ·R ≠ G');
  await expect(alert).toContainText('the revealed Γ does not match the γ used in MtA');
  await expect(alert).toContainText('Σ σᵢ·R ≠ X');
  await expect(alert).toContainText('This is detection, not attribution');

  // Phase-5 and the final verification never disagree (the README's claim).
  await expect(page.locator('.verify-line')).toContainText('✗ invalid');
  await page.locator('#sign-verify').click();
  const echo = page.locator('#exhibit-4 [aria-live] p.mono').filter({ hasText: 'secp256k1.verify' });
  await expect(echo).toContainText('→ false ✗');
  await expect(echo).toHaveClass(/danger/);

  // Untick and re-sign: the verdict tracks the run, not a sticky failure flag.
  await page.locator('#cheat').uncheck();
  await runSigning(page);
  await expect(page.locator('[role="alert"]')).toHaveCount(0);
  await expect(page.locator('.p5-verdict')).toContainText('✓ both identities hold');
  await expect(page.locator('.verify-line')).toContainText('✓ valid standard ECDSA signature');
  const kR2 = clip(await rows.nth(0).locator('.p5-got').innerText());
  expect(G_COMPRESSED.startsWith(kR2)).toBe(true);
});

test('re-verifying against an edited message reports false — and is styled as a failure', async ({
  page,
}) => {
  // Regression: the echo used to take its colour from the *previous* run's
  // verdict, so a genuine "false ✗" could render in the success style.
  await buildWallet(page);
  await runSigning(page);
  await page.locator('#sign-verify').click();
  const echo = page.locator('#exhibit-4 [aria-live] p.mono').filter({ hasText: 'secp256k1.verify' });
  await expect(echo).toContainText('→ true ✓');

  await page.locator('#message').fill('a different transaction than the one that was signed');
  await page.locator('#sign-verify').click();
  await expect(echo).toContainText('→ false ✗');
  await expect(echo).toHaveClass(/danger/);
  await expect(echo).not.toHaveClass(/ok/);
});

test('regenerating a party invalidates the signature and re-gates signing', async ({ page }) => {
  await buildWallet(page);
  await runSigning(page);
  await expect(page.locator('.verify-line')).toContainText('✓ valid');

  await page.locator('#dkg-p1').click();
  await expect(page.locator('#dkg-p1')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('.verify-line')).toContainText('Pending — run signing above');
  await expect(page.locator('.p5-verdict')).toContainText('Pending');
  await expect(page.locator('#sign-run')).toBeDisabled();
  await expect(page.locator('#sign-verify')).toBeDisabled();
  await expect(page.locator('#exhibit-3 [aria-live] p.accent')).toContainText('X₁ + X₂: —');
});

// ---------- Exhibit 6: the runnable range proof ----------

test('an honest range proof passes all four checks and the verdict is their conjunction', async ({
  page,
}) => {
  await expect(page.locator('#zk-honest')).toBeDisabled();
  await expect(page.locator('#zk-malicious')).toBeDisabled();
  await zkSetup(page);
  await expect(page.locator('#exhibit-6 [aria-live]')).toContainText(/Paillier n: 0x[0-9a-f]+/);
  await expect(page.locator('#exhibit-6 [aria-live]')).toContainText(/Aux Ñ: 0x[0-9a-f]+/);

  await page.locator('#zk-honest').click();
  const verdict = zkLine(page, 'verdict:', 0);
  await expect(verdict).toBeVisible({ timeout: 120_000 });

  for (const mark of ['①', '②', '③', '④']) {
    await expect(zkLine(page, mark, 0)).toContainText('✓ pass');
    await expect(zkLine(page, mark, 0)).toHaveClass(/ok/);
  }
  await expect(verdict).toContainText('✓ accepted');
  await expect(verdict).toContainText('the plaintext is proven to lie in [0, q) — without revealing it');
  await expect(verdict).toHaveClass(/ok/);

  // The bound the page reports must be the real q³, and the honest response
  // must actually fit under it — the arithmetic behind check ①.
  const s1Line = await zkLine(page, 's₁ = e·m + α', 0).innerText();
  const s1Bits = Number(bigAt(s1Line, /(\d+) bits/));
  const boundBits = Number(bigAt(s1Line, /range bound q³ = (\d+) bits/));
  expect(boundBits).toBe(RANGE_BOUND_BITS);
  expect(boundBits).toBe(768);
  expect(s1Bits).toBeLessThanOrEqual(boundBits);
  await expect(zkLine(page, 'm (secret plaintext', 0)).toContainText('a valid share < q (256 bits)');
});

test('an out-of-range prover (m ≈ N) is rejected by the range bound alone', async ({ page }) => {
  await zkSetup(page);
  await page.locator('#zk-malicious').click();
  const verdict = zkLine(page, 'verdict:', 0); // only the malicious block has run
  await expect(verdict).toBeVisible({ timeout: 120_000 });

  // The cheater's algebra is impeccable; only the fence stops them. That is the
  // entire teaching point of this exhibit, so assert it check by check.
  await expect(zkLine(page, '①', 0)).toContainText('✗ FAIL');
  await expect(zkLine(page, '①', 0)).toHaveClass(/danger/);
  for (const mark of ['②', '③', '④']) {
    await expect(zkLine(page, mark, 0)).toContainText('✓ pass');
    await expect(zkLine(page, mark, 0)).toHaveClass(/ok/);
  }
  await expect(verdict).toContainText('✗ rejected');
  await expect(verdict).toContainText('rejected by the RANGE BOUND ALONE');
  await expect(verdict).toHaveClass(/danger/);

  // The response really is out of range, by the page's own bit counts, and the
  // rejection reason quotes the same numbers it displayed above.
  const s1Line = await zkLine(page, 's₁ = e·m + α', 0).innerText();
  const s1Bits = Number(bigAt(s1Line, /(\d+) bits/));
  const boundBits = Number(bigAt(s1Line, /range bound q³ = (\d+) bits/));
  expect(boundBits).toBe(RANGE_BOUND_BITS);
  expect(s1Bits).toBeGreaterThan(boundBits);
  const reason = await verdict.innerText();
  expect(Number(bigAt(reason, /s₁ has (\d+) bits/))).toBe(s1Bits);
  expect(Number(bigAt(reason, /q³ bound of (\d+)/))).toBe(boundBits);

  // m ≈ N: a ~1024-bit plaintext (two 512-bit primes, so 1023 or 1024 bits)
  // where an honest share is 256-bit — far past the q³ fence on its own.
  const mBits = Number(bigAt(await zkLine(page, 'm (secret plaintext', 0).innerText(), /(\d+) bits/));
  expect(mBits).toBeGreaterThan(boundBits);
  expect(mBits).toBeGreaterThanOrEqual(1023);
  expect(mBits).toBeLessThanOrEqual(1024);

  // The number-line callout is wired to the run that just happened.
  await expect(page.locator('.wl-caption')).toContainText(
    'you just triggered this: the malicious run failed the fence check below'
  );
});

test('both provers run side by side: honest accepted, malicious rejected, same setup', async ({
  page,
}) => {
  await zkSetup(page);
  await page.locator('#zk-honest').click();
  await expect(zkLine(page, 'verdict:', 0)).toBeVisible({ timeout: 120_000 });
  await page.locator('#zk-malicious').click();
  await expect(zkLine(page, 'verdict:', 1)).toBeVisible({ timeout: 120_000 });

  await expect(zkLine(page, 'verdict:', 0)).toContainText('✓ accepted');
  await expect(zkLine(page, 'verdict:', 1)).toContainText('✗ rejected');
  await expect(zkLine(page, '①', 0)).toContainText('✓ pass');
  await expect(zkLine(page, '①', 1)).toContainText('✗ FAIL');
  // Same trusted setup, same verifier, opposite outcomes — the difference is
  // the witness, which is the claim the exhibit makes.
  for (const mark of ['②', '③', '④']) {
    await expect(zkLine(page, mark, 0)).toContainText('✓ pass');
    await expect(zkLine(page, mark, 1)).toContainText('✓ pass');
  }
});

// ---------- Exhibit 7: the implemented/described ledger ----------

test("Exhibit 7's \"implemented\" rows are backed by exhibits that actually run", async ({
  page,
}) => {
  const row = (name: string): Locator =>
    page.locator('#exhibit-7 tbody tr').filter({ hasText: name });
  await expect(row('Phase-5 checks')).toContainText('✓ implemented (Exhibit 4)');
  await expect(row('MtA range proof')).toContainText('✓ implemented (Exhibit 6)');
  await expect(row('Paillier–Blum proof')).toContainText('○ assumed honest');
  await expect(row('MtA DL-binding')).toContainText('○ described');
  await expect(row('Type-5/7 blame phase')).toContainText('○ described');

  // The two "✓ implemented" rows point at panels that produce live verdicts.
  await buildWallet(page);
  await runSigning(page);
  await expect(page.locator('.p5-verdict')).toContainText('✓ both identities hold');
  await zkSetup(page);
  await page.locator('#zk-honest').click();
  await expect(zkLine(page, 'verdict:', 0)).toContainText('✓ accepted', { timeout: 120_000 });
});
