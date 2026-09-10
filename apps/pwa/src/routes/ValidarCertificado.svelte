<script lang="ts">
import type { CertCheckResult } from '@firma-ec/verifier';
/**
 * ValidarCertificado.svelte — cert-only validation flow.
 *
 * Distinct from Verificar.svelte (which verifies a signed PDF). Here the user
 * uploads a .p12/.pfx + PIN; the app parses the certificate and reports its
 * titular, emisor/ACE, serial, validity window + estado, and whether it chains
 * to an ARCOTEL-accredited root. NO PDF, NO signing.
 *
 * Crypto stays in a single-shot worker (cert.worker via cert-bus). The PIN +
 * PFX bytes never survive the call and the private key NEVER crosses back.
 *
 * Mirrors FirmaEC 5.1.0's "Validar Certificado" tab.
 */
import { getLang, t } from '../lib/i18n.svelte.ts';
import { pingUsage } from '../lib/statsBeacon.ts';
import { CertWorkerError, checkCertInWorker } from '../lib/workers/cert-bus.ts';
import DropP12 from '../ui/firma/DropP12.svelte';

type Phase = 'idle' | 'running' | 'done' | 'error';

let phase = $state<Phase>('idle');
let pfxBytes = $state<Uint8Array | null>(null);
let pin = $state<string>('');
let showPin = $state<boolean>(false);
let result = $state<CertCheckResult | null>(null);
let errorKey = $state<'validar_cert.error_pin' | 'validar_cert.error_parse' | null>(null);
let errorDetail = $state<{ code: string; message: string } | null>(null);

let pinInputEl = $state<HTMLInputElement | undefined>();

function onP12({ p12, fileName: _fileName }: { p12: ArrayBuffer; fileName: string }): void {
  errorKey = null;
  errorDetail = null;
  result = null;
  pfxBytes = new Uint8Array(p12);
  pin = '';
  // Focus the PIN field once the cert is dropped (next tick).
  queueMicrotask(() => pinInputEl?.focus());
}

function onP12Error(_key: 'firmar.step3.error_too_large' | 'firmar.step3.error_not_p12'): void {
  errorKey = 'validar_cert.error_parse';
  errorDetail = null;
}

async function onSubmit(): Promise<void> {
  if (!pfxBytes || !pin || phase === 'running') return;
  errorKey = null;
  errorDetail = null;
  phase = 'running';
  try {
    // Defensive copy: the worker transfers (detaches) the buffer.
    const copy = new Uint8Array(pfxBytes);
    const r = await checkCertInWorker(copy.buffer, pin);
    result = r;
    phase = 'done';
    // Anonymous usage tally for the public counter (no PII, no cert data).
    pingUsage('cert');
    // Wipe sensitive input ASAP — the result holds only public cert fields.
    pin = '';
  } catch (e) {
    const code = e instanceof CertWorkerError ? e.code : 'unknown';
    if (code === 'pin_invalid' || code === 'bad_pin') {
      errorKey = 'validar_cert.error_pin';
    } else {
      errorKey = 'validar_cert.error_parse';
    }
    errorDetail = { code, message: e instanceof Error ? e.message : String(e) };
    phase = 'error';
    pin = '';
  }
}

function onPinKeydown(ev: KeyboardEvent): void {
  if (ev.key === 'Enter') {
    ev.preventDefault();
    void onSubmit();
  }
}

function reset(): void {
  phase = 'idle';
  pfxBytes = null;
  pin = '';
  showPin = false;
  result = null;
  errorKey = null;
  errorDetail = null;
}

function fmtDate(iso: string): string {
  try {
    return new Intl.DateTimeFormat(getLang() === 'es' ? 'es-EC' : 'en-US', {
      dateStyle: 'medium',
      timeStyle: 'medium',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

// Card colour: trusted + valid = ok; parsed-but-untrusted = warn; expired /
// not-yet-valid = err (same token vocabulary as Verificar).
const cardClass = $derived.by((): string => {
  if (!result) return 'border-ink-300/50 dark:border-ink-700/60 bg-ink-100/60 dark:bg-ink-900/40';
  if (result.validityStatus !== 'valid' || result.revocationStatus === 'revoked')
    return 'border-err-500/40 bg-err-500/10';
  if (result.trusted) return 'border-ok-500/40 bg-ok-500/10';
  return 'border-warn-500/40 bg-warn-500/10';
});

const cardIcon = $derived.by((): string => {
  if (!result) return 'i-lucide-shield text-ink-500';
  if (result.validityStatus !== 'valid' || result.revocationStatus === 'revoked')
    return 'i-lucide-shield-x text-err-500';
  if (result.trusted) return 'i-lucide-shield-check text-ok-500';
  return 'i-lucide-shield-alert text-warn-500';
});

/**
 * A quien pertenece el RUC. El de una persona natural es su cedula mas el
 * codigo de establecimiento, asi que EMPIEZA por la cedula; el de una empresa
 * no. La fila se pintaba con la etiqueta «RUC» a secas aunque faltara la razon
 * social —pasa cuando la ACE no esta en ACE_ARCS y el RUC sale del
 * organizationIdentifier del DN—, y ahi el numero de una empresa se leia como
 * un dato del titular: justo el error que esta pantalla existe para evitar.
 */
const rucLabel = $derived.by((): string => {
  if (!result?.ruc) return t('validar_cert.field_ruc');
  const esDelTitular = result.cedula !== undefined && result.ruc.startsWith(result.cedula);
  return esDelTitular ? t('validar_cert.field_ruc') : t('validar_cert.field_ruc_empresa');
});

function statusLabel(s: CertCheckResult['validityStatus']): string {
  if (s === 'expired') return t('validar_cert.status_expired');
  if (s === 'not_yet_valid') return t('validar_cert.status_not_yet');
  return t('validar_cert.status_valid');
}

// "Revocado" cell text. The check is offline-tolerant: when the OCSP/CRL
// cascade can't reach ARCOTEL it returns 'unknown' → "No verificable".
function revocationLabel(s: CertCheckResult['revocationStatus']): string {
  if (s === 'revoked') return t('common.yes');
  if (s === 'good') return t('common.no');
  if (s === 'unchecked') return t('validar_cert.revoked_unchecked');
  return t('validar_cert.revoked_unknown');
}
</script>

<section class="container max-w-3xl mx-auto px-4 py-12 md:py-16">
  <header class="mb-8">
    <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight mb-2">
      {t('validar_cert.title')}
    </h1>
    <p class="text-ink-500 text-base md:text-lg">
      {t('validar_cert.subtitle')}
    </p>
  </header>

  {#if phase !== 'done'}
    <div class="flex flex-col gap-6">
      <DropP12 onp12={onP12} onerror={onP12Error} disabled={phase === 'running'} />

      {#if pfxBytes}
        <form autocomplete="off" onsubmit={(e) => { e.preventDefault(); void onSubmit(); }}>
          <label class="block">
            <span class="text-sm font-medium text-ink-700 dark:text-ink-200 mb-2 block">
              {t('validar_cert.pin_label')}
            </span>
            <div class="relative">
              <input
                bind:this={pinInputEl}
                type={showPin ? 'text' : 'password'}
                inputmode="text"
                autocomplete="off"
                autocapitalize="off"
                autocorrect="off"
                spellcheck="false"
                enterkeyhint="done"
                name=""
                data-1p-ignore
                data-lpignore="true"
                data-form-type="other"
                disabled={phase === 'running'}
                bind:value={pin}
                onkeydown={onPinKeydown}
                aria-invalid={errorKey === 'validar_cert.error_pin' ? 'true' : undefined}
                class="
                  w-full h-14 pr-14 pl-4 rounded-md
                  border border-ink-300 dark:border-ink-700
                  bg-ink-50 dark:bg-ink-900
                  text-ink-900 dark:text-ink-50
                  font-mono tracking-widest
                  focus:outline-none focus:border-brand-500
                  disabled:opacity-60 disabled:cursor-not-allowed
                "
                class:border-err-500={errorKey === 'validar_cert.error_pin'}
              />
              <button
                type="button"
                aria-label={showPin ? t('firmar.aria.pin_hide') : t('firmar.aria.pin_show')}
                aria-pressed={showPin}
                onclick={() => { showPin = !showPin; queueMicrotask(() => pinInputEl?.focus()); }}
                disabled={phase === 'running'}
                class="
                  absolute top-1/2 right-1 -translate-y-1/2
                  w-11 h-11 rounded-md
                  flex items-center justify-center
                  text-ink-500 hover:text-ink-700 dark:hover:text-ink-200
                  focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500
                "
              >
                <span
                  class="text-lg"
                  class:i-lucide-eye-off={showPin}
                  class:i-lucide-eye={!showPin}
                  aria-hidden="true"
                ></span>
              </button>
            </div>
          </label>

          <button
            type="submit"
            disabled={!pin || phase === 'running'}
            class="
              mt-6 w-full sm:w-auto inline-flex items-center justify-center gap-2
              h-12 px-6 rounded-md
              bg-brand-500 hover:bg-brand-600 active:scale-[0.98]
              text-white font-medium
              transition-all duration-100
              disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-brand-500
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-50 dark:focus-visible:ring-offset-ink-950
            "
          >
            {#if phase === 'running'}
              <span class="i-lucide-loader-2 text-base animate-spin" aria-hidden="true"></span>
            {:else}
              <span class="i-lucide-shield-check text-base" aria-hidden="true"></span>
            {/if}
            {t('validar_cert.submit')}
          </button>
        </form>
      {/if}

      {#if phase === 'error' && errorKey}
        <div role="alert" class="rounded-2xl border border-err-500/40 bg-err-500/10 px-7 py-6 flex items-start gap-3">
          <span class="i-lucide-x-circle text-2xl text-err-500 shrink-0 mt-0.5" aria-hidden="true"></span>
          <div class="flex-1 min-w-0">
            <p class="text-ink-700 dark:text-ink-200">{t(errorKey)}</p>
            {#if errorDetail}
              <details class="mt-3 text-sm">
                <summary class="cursor-pointer text-ink-500 hover:text-ink-700 dark:hover:text-ink-200 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 rounded">
                  {t('error.engine_show_technical')}
                </summary>
                <p class="mt-2 break-words">
                  <span class="font-mono text-xs text-err-500">{errorDetail.code}</span>
                  <span class="ml-2 text-ink-600 dark:text-ink-300">{errorDetail.message}</span>
                </p>
              </details>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {:else if phase === 'done' && result}
    <div class="flex flex-col gap-6">
      <div role="status" class="rounded-2xl border px-7 py-6 flex flex-col gap-5 {cardClass}">
        <div class="flex items-start gap-3">
          <span class="{cardIcon} text-2xl shrink-0 mt-0.5" aria-hidden="true"></span>
          <div class="flex-1 min-w-0">
            <h2 class="font-display font-semibold text-lg text-ink-800 dark:text-ink-100">
              {result.subjectCN || t('validar_cert.field_titular')}
            </h2>
            {#if !result.trusted}
              <p class="text-sm text-ink-700 dark:text-ink-200 mt-1">
                {t('validar_cert.not_accredited')}
              </p>
            {/if}
          </div>
        </div>

        <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
          <dt class="text-ink-500">{t('validar_cert.field_titular')}</dt>
          <dd class="text-ink-800 dark:text-ink-100 break-words">{result.subjectCN || '—'}</dd>

          {#if result.givenName}
            <dt class="text-ink-500">{t('validar_cert.field_nombres')}</dt>
            <dd class="text-ink-800 dark:text-ink-100 break-words">{result.givenName}</dd>
          {/if}

          {#if result.surname}
            <dt class="text-ink-500">{t('validar_cert.field_apellidos')}</dt>
            <dd class="text-ink-800 dark:text-ink-100 break-words">{result.surname}</dd>
          {/if}

          {#if result.cedula}
            <dt class="text-ink-500">{t('validar_cert.field_cedula')}</dt>
            <dd class="text-ink-800 dark:text-ink-100 font-mono break-all">{result.cedula}</dd>
          {/if}

          <!-- Legal-representative block: RUC + razón social + cargo, el mismo
               trio que muestra FirmaEC 5.1.0. La etiqueta del RUC dice de quien
               es (ver `rucLabel`), porque la razón social puede faltar y el
               número solo se lee bien sabiendo a quién pertenece. -->
          {#if result.ruc}
            <dt class="text-ink-500">{rucLabel}</dt>
            <dd class="text-ink-800 dark:text-ink-100 font-mono break-all">{result.ruc}</dd>
          {/if}

          {#if result.organization}
            <dt class="text-ink-500">{t('validar_cert.field_razon_social')}</dt>
            <dd class="text-ink-800 dark:text-ink-100 break-words">{result.organization}</dd>
          {/if}

          {#if result.jobTitle}
            <dt class="text-ink-500">{t('validar_cert.field_cargo')}</dt>
            <dd class="text-ink-800 dark:text-ink-100 break-words">{result.jobTitle}</dd>
          {/if}

          <dt class="text-ink-500">{t('validar_cert.field_emisor')}</dt>
          <dd class="text-ink-800 dark:text-ink-100 break-words">
            {result.matchedAceOrg ?? result.issuerCN ?? '—'}
          </dd>

          <dt class="text-ink-500">{t('validar_cert.field_serie')}</dt>
          <dd class="text-ink-800 dark:text-ink-100 font-mono text-xs break-all">
            {result.serialHex || '—'}
          </dd>

          <dt class="text-ink-500">{t('validar_cert.field_desde')}</dt>
          <dd class="text-ink-800 dark:text-ink-100">{fmtDate(result.notBefore)}</dd>

          <dt class="text-ink-500">{t('validar_cert.field_hasta')}</dt>
          <dd class="text-ink-800 dark:text-ink-100">{fmtDate(result.notAfter)}</dd>

          <dt class="text-ink-500">{t('validar_cert.field_estado')}</dt>
          <dd
            class="font-medium"
            class:text-ok-600={result.validityStatus === 'valid'}
            class:dark:text-ok-400={result.validityStatus === 'valid'}
            class:text-err-600={result.validityStatus !== 'valid'}
            class:dark:text-err-400={result.validityStatus !== 'valid'}
          >
            {statusLabel(result.validityStatus)}
          </dd>

          <dt class="text-ink-500">{t('validar_cert.field_expirado')}</dt>
          <dd
            class="font-medium"
            class:text-ok-600={result.validityStatus !== 'expired'}
            class:dark:text-ok-400={result.validityStatus !== 'expired'}
            class:text-err-600={result.validityStatus === 'expired'}
            class:dark:text-err-400={result.validityStatus === 'expired'}
          >
            {result.validityStatus === 'expired' ? t('common.yes') : t('common.no')}
          </dd>

          <dt class="text-ink-500">{t('validar_cert.field_revocado')}</dt>
          <dd
            class="font-medium"
            class:text-ok-600={result.revocationStatus === 'good'}
            class:dark:text-ok-400={result.revocationStatus === 'good'}
            class:text-err-600={result.revocationStatus === 'revoked'}
            class:dark:text-err-400={result.revocationStatus === 'revoked'}
            class:text-warn-600={result.revocationStatus === 'unknown' || result.revocationStatus === 'unchecked'}
            class:dark:text-warn-400={result.revocationStatus === 'unknown' || result.revocationStatus === 'unchecked'}
          >
            {revocationLabel(result.revocationStatus)}{#if result.revocationStatus === 'revoked' && result.revokedAt}
              <span class="text-ink-500 font-normal"> · {fmtDate(result.revokedAt)}</span>
            {/if}
          </dd>

          <dt class="text-ink-500">{t('validar_cert.field_cadena')}</dt>
          <dd
            class="font-medium"
            class:text-ok-600={result.trusted}
            class:dark:text-ok-400={result.trusted}
            class:text-warn-600={!result.trusted}
            class:dark:text-warn-400={!result.trusted}
          >
            {result.trusted ? t('validar_cert.chain_trusted') : t('validar_cert.chain_untrusted')}
          </dd>
        </dl>
      </div>

      <div class="flex justify-center">
        <button
          type="button"
          onclick={reset}
          class="inline-flex items-center gap-2 h-11 px-5 rounded-md border border-ink-300 dark:border-ink-700 bg-ink-50 dark:bg-ink-900 hover:bg-ink-100 dark:hover:bg-ink-800 text-ink-700 dark:text-ink-100 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-50 dark:focus-visible:ring-offset-ink-950"
        >
          <span class="i-lucide-rotate-ccw text-base" aria-hidden="true"></span>
          {t('validar_cert.reset')}
        </button>
      </div>
    </div>
  {/if}
</section>
