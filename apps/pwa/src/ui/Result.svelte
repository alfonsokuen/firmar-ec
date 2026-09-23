<script lang="ts">
/**
 * Result.svelte — top-level verdict card.
 *
 * Maps `VerificationResult.status` to a colour family + lucide icon + title +
 * one-line summary. Visually mirrors the F1 v0.1.2 estética premium (rounded
 * card, subtle glow, ample padding, focus-friendly contrast).
 */
import type { VerificationResult } from '@firma-ec/verifier';
import { type UIKey, t } from '../lib/i18n.svelte.ts';

interface Props {
  result: VerificationResult;
}

const { result }: Props = $props();

type Variant = {
  icon: string;
  title: UIKey;
  summary: UIKey;
  /** Tailwind / UnoCSS colour class slice */
  iconBg: string;
  iconText: string;
  border: string;
  glow: string;
};

const VARIANTS: Record<VerificationResult['status'], Variant> = {
  valid: {
    icon: 'i-lucide-check-circle',
    title: 'verificar.valid',
    summary: 'verificar.valid_summary',
    iconBg: 'bg-ok-500/15',
    iconText: 'text-ok-500',
    border: 'border-ok-500/40',
    glow: 'shadow-[0_0_0_4px_oklch(64%_0.16_145_/_0.12)]',
  },
  warning: {
    icon: 'i-lucide-alert-triangle',
    title: 'verificar.warning',
    summary: 'verificar.warning_summary',
    iconBg: 'bg-warn-500/15',
    iconText: 'text-warn-500',
    border: 'border-warn-500/40',
    glow: 'shadow-[0_0_0_4px_oklch(74%_0.17_80_/_0.12)]',
  },
  invalid: {
    icon: 'i-lucide-x-circle',
    title: 'verificar.invalid',
    summary: 'verificar.invalid_summary',
    iconBg: 'bg-err-500/15',
    iconText: 'text-err-500',
    border: 'border-err-500/40',
    glow: 'shadow-[0_0_0_4px_oklch(58%_0.21_25_/_0.12)]',
  },
  no_signature: {
    icon: 'i-lucide-file-x',
    title: 'verificar.no_signature',
    summary: 'verificar.no_signature_summary',
    iconBg: 'bg-ink-300/30',
    iconText: 'text-ink-500',
    border: 'border-ink-300 dark:border-ink-700',
    glow: '',
  },
};

const v = $derived(VARIANTS[result.status]);

// A chain valid only at the signer-declared date is not "valid with minor
// warnings": the date is the signer's word. Give it its own title.
const signingTimeUnproven = $derived(
  result.status === 'warning' && result.warnings.some((w) => w.code === 'signing_time_unproven'),
);
const titleKey = $derived<UIKey>(signingTimeUnproven ? 'verificar.warning_unproven_time' : v.title);

/**
 * For 'invalid' status, pick a specific summary key based on which warning
 * the verifier surfaced. This avoids the misleading generic "documento
 * modificado" message when the actual cause is e.g. an untrusted root or an
 * incomplete chain.
 *
 * CHAIN_INCOMPLETE_UNKNOWN_INTERMEDIATE (2026-08-05, CRITICAL security fix):
 * this code is surfaced under `status: 'invalid'`, NOT 'warning' — a chain
 * the verifier couldn't complete is always a hard rejection, because the
 * pool used to walk the chain includes attacker-controlled CMS content (see
 * pathValidation.ts). The message is just honest about the two possible
 * causes (a bundled-intermediate gap vs. an unaccredited issuer) instead of
 * outright accusing the user of fraud — it never implies the signature might
 * still be trustworthy.
 */
const summaryKey = $derived.by<UIKey>(() => {
  const codes = new Set(result.warnings.map((w) => w.code));
  if (signingTimeUnproven) return 'verificar.warning_summary_unproven_time';
  if (result.status !== 'invalid') return v.summary;
  // Hash mismatch / bad signature are the only true integrity failures.
  // `integrity` is absent when verification threw (engine-error path in
  // index.ts catch → status:'invalid' with no integrity). Guard so the result
  // card never crashes; an engine error falls through to the generic summary
  // instead of being mislabeled "documento modificado".
  if (result.integrity && !result.integrity.digestMatches)
    return 'verificar.invalid_summary_hash_mismatch';
  if (codes.has('cert_revoked')) return 'verificar.invalid_summary_revoked';
  if (codes.has('CHAIN_INCOMPLETE_UNKNOWN_INTERMEDIATE'))
    return 'verificar.invalid_summary_chain_incomplete';
  if (codes.has('key_usage_not_signing')) return 'verificar.invalid_summary_key_usage';
  if (codes.has('signer_cert_not_valid')) return 'verificar.invalid_summary_cert_not_valid';
  if (codes.has('untrusted_root')) return 'verificar.invalid_summary_untrusted_root';
  // Fallback: signature value invalid (no specific warning code path).
  return 'verificar.invalid_summary_bad_signature';
});
</script>

<section
  role="alert"
  aria-live="polite"
  class="w-full rounded-2xl border bg-ink-50 dark:bg-ink-900 px-7 py-6 flex items-start gap-4 {v.border} {v.glow}"
>
  <div
    class="shrink-0 w-12 h-12 rounded-xl flex items-center justify-center {v.iconBg}"
  >
    <span class="{v.icon} text-2xl {v.iconText}" aria-hidden="true"></span>
  </div>

  <div class="flex-1 min-w-0">
    <h2 class="text-xl sm:text-2xl font-display font-semibold tracking-tight {v.iconText}">
      {t(titleKey)}
    </h2>
    <p class="mt-1 text-sm sm:text-base text-ink-600 dark:text-ink-300">
      {t(summaryKey)}
    </p>

    {#if result.signer?.cert.subject.cn}
      <p class="mt-3 text-sm text-ink-700 dark:text-ink-200">
        <span class="text-ink-500">{t('detail.signer')}:</span>
        <span class="font-medium">{result.signer.cert.subject.cn}</span>
      </p>
    {/if}
  </div>
</section>
