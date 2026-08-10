/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#cl-theme-toggle.cl-btn.cl-icon": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#dkg-joint": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#dkg-p1": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#dkg-p2": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#mta-next": { ratio: 1.49, required: 3.0, unverified: false },
  "control-boundary|button#mta-reset": { ratio: 1.49, required: 3.0, unverified: false },
  "control-boundary|button#mta-run": { ratio: 1.49, required: 3.0, unverified: false },
  "control-boundary|button#paillier-add": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#paillier-keygen": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#paillier-scalar": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#self-test": { ratio: 1.61, required: 3.0, unverified: false },
  "control-boundary|button#sign-run": { ratio: 1.61, required: 3.0, unverified: false },
  "control-boundary|button#sign-verify": { ratio: 1.61, required: 3.0, unverified: false },
  "control-boundary|button#zk-honest": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#zk-malicious": { ratio: 1.6, required: 3.0, unverified: false },
  "control-boundary|button#zk-setup": { ratio: 1.6, required: 3.0, unverified: false }
};
