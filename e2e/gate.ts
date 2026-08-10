import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     ran a `revealAll()` that forced every `<details>` open, stripped every
 *     `[hidden]`, cleared every inline `display: none` and added `.open`,
 *     `.active` and `.expanded` to anything that already had one of them. That
 *     is a FABRICATED page: it scans renderings the app never produces while
 *     leaving the real post-interaction states — a completed signing, a
 *     rejected malicious proof — unvisited, because those need clicks, not
 *     attribute edits.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and at first paint this lab's eight exhibits are almost all
 *     placeholders: no Paillier keypair, no DKG shares, no MtA trace, no
 *     signature, no range proof. The verdict lines a learner reads — the
 *     Phase-5 identities, the identifiable abort, the rejected malicious
 *     prover — do not exist until something is run.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The old gate asserted
 *     on `violations` plus one "gradient contrast check" that did not measure
 *     the page at all: it created two throwaway divs, read `var(--background)`
 *     and `var(--text)` off them, and compared those two tokens. Neither token
 *     exists in this stylesheet (the names are `--bg` and `--text`), so
 *     `--background` resolved to nothing, `parseRGB` returned its `[0, 0, 0]`
 *     fallback, and the check compared the page text against black and passed.
 *     It could not have failed for any real reason.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block collapses durations to 0.01ms rather than cancelling,
 * which preserves end states; the assertion stays because it is cheap and the
 * block is the kind of thing that grows.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. The gate this replaced called
 * `emulateMedia({ reducedMotion: 'reduce' })` and never checked it took effect,
 * which is indistinguishable from not calling it.
 *
 * The theme is seeded in `localStorage` rather than reached by clicking the
 * toggle, so the light run boots light instead of ramping into it.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered into #app by JS, so an empty shell would
  // otherwise scan clean. Assert all eight exhibits and the first controls.
  await expect(page.locator('section.exhibit')).toHaveCount(9);
  await expect(page.locator('#paillier-keygen')).toBeVisible();
  await expect(page.locator('#zk-setup')).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 1024-bit Paillier moduli and secp256k1 points
 * as long unbroken tokens, lays the signing output out as a three-column party
 * diagram, and draws an absolutely-positioned number line whose right-hand
 * label is `white-space: nowrap`.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}





/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The exhibits are strictly ordered: Paillier keygen enables the homomorphic
 * buttons, DKG enables signing, the trusted setup enables both provers. A drive
 * that skips a prerequisite does not fail — it hangs on a permanently disabled
 * control, which is why `boot` sets a 20s default timeout so that shows up as a
 * named failure rather than a silent stall.
 *
 * Both branches of every verdict are reached: an honest signing that verifies
 * AND a malicious Party 2 that trips the Phase-5 identities into an
 * identifiable abort; an honest range proof that is accepted AND a
 * near-modulus one that is rejected. Those failure renderings are the whole
 * point of the lab and none of them exist until a button is clicked.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // The two disclosures are real states a visitor opens, not something to force
  // open before a single scan the way the old gate did.
  for (const d of await page.locator('details > summary').all()) await d.click();
  await scan(page, `${theme} / disclosures open`);
  for (const d of await page.locator('details > summary').all()) await d.click();

  // --- Exhibit 2: Paillier ------------------------------------------------
  await page.locator('#paillier-keygen').click();
  await expect(page.locator('#paillier-add')).toBeEnabled();
  await scan(page, `${theme} / paillier keypair`);

  await page.locator('#paillier-add').click();
  await scan(page, `${theme} / paillier homomorphic add`);

  await page.locator('#paillier-scalar').click();
  await scan(page, `${theme} / paillier scalar multiply`);

  // --- Exhibit 3: distributed key generation ------------------------------
  // 1024-bit keygen is slow; the button disables itself while it runs.
  await page.locator('#dkg-p1').click();
  await expect(page.locator('#dkg-p1')).toBeEnabled({ timeout: 60_000 });
  await scan(page, `${theme} / dkg party 1`);

  await page.locator('#dkg-p2').click();
  await expect(page.locator('#dkg-joint')).toBeEnabled({ timeout: 60_000 });
  await scan(page, `${theme} / dkg party 2`);

  await page.locator('#dkg-joint').click();
  await expect(page.locator('#sign-run')).toBeEnabled();
  await scan(page, `${theme} / joint public key`);

  // --- Exhibit 4: MtA walkthrough ----------------------------------------
  await page.locator('#mta-run').click();
  await expect(page.locator('#mta-next')).toBeEnabled();
  await scan(page, `${theme} / mta example loaded`);

  // The reveal runs 1..5 and `mta-run` already leaves it at 1, so there are
  // FOUR further clicks — a fifth would sit on a permanently disabled button.
  for (let step = 2; step <= 5; step++) {
    await page.locator('#mta-next').click();
    await scan(page, `${theme} / mta step ${step}`);
  }
  await page.locator('#mta-reset').click();
  await scan(page, `${theme} / mta reset`);

  // --- Exhibit 4: signing, both branches ----------------------------------
  await page.locator('#message').fill('pay alice 1 btc');
  await page.locator('#sign-run').click();
  await expect(page.locator('.verify-line')).toContainText('valid standard ECDSA');
  await scan(page, `${theme} / signing verified`);

  await page.locator('#sign-verify').click();
  await scan(page, `${theme} / independently verified`);

  // The malicious branch: Phase-5 detects the deviation and the run aborts.
  await page.locator('#cheat').check();
  await page.locator('#sign-run').click();
  await expect(page.locator('[role="alert"]')).toContainText('Identifiable abort');
  await scan(page, `${theme} / identifiable abort`);

  await page.locator('#cheat').uncheck();
  await page.locator('#sign-run').click();
  await expect(page.locator('.verify-line')).toContainText('valid standard ECDSA');

  // 25 random signings — the exhibit's own proof of its central claim.
  await page.locator('#self-test').click();
  await expect(page.locator('#self-test')).toBeEnabled({ timeout: 120_000 });
  await scan(page, `${theme} / self-test complete`);

  // --- Exhibit 6: zero-knowledge range proof, both branches ---------------
  await page.locator('#zk-setup').click();
  await expect(page.locator('#zk-honest')).toBeEnabled({ timeout: 60_000 });
  await scan(page, `${theme} / zk trusted setup`);

  await page.locator('#zk-honest').click();
  await scan(page, `${theme} / zk honest prover accepted`);

  await page.locator('#zk-malicious').click();
  await scan(page, `${theme} / zk malicious prover rejected`);

  // A glossary term shown the way a visitor shows one — the gloss is the
  // lab's inline notation decoder and it only paints on hover/focus.
  const gloss = page.locator('.gloss').first();
  await gloss.focus();
  await scan(page, `${theme} / glossary term focused`);

  // The skip link is parked off-screen until focused; the focused rendering is
  // the only one that paints, so it is the only one worth measuring.
  await page.keyboard.press('Home');
  await page.locator('body').press('Tab');
  await scan(page, `${theme} / skip link focused`);
}
