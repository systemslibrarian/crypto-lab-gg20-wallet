import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * All eight exhibits are driven in protocol order — Paillier keygen and its two
 * homomorphic operations, both DKG parties and the joint public key, the
 * five-step MtA walkthrough, an honest signing plus a malicious Party 2 that
 * trips Phase-5 into an identifiable abort, the 25-signature self-test, the ZK
 * trusted setup and BOTH provers — with every resulting rendering scanned in
 * both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected or force-revealed, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
