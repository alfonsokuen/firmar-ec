/**
 * intermediates.ts — Subordinate CA certificates for TSAs whose timestamp
 * tokens do NOT chain directly to a self-signed TSA trust root.
 *
 * Mirrors `@firma-ec/tsl-ec`'s `intermediates.ts` (same rationale: many CAs
 * ship RFC 3161 tokens leaf-only, assuming verifiers fetch the issuing
 * subordinate CA via AIA or already have it bundled). Kept as a SEPARATE
 * list from tsl-ec on purpose — see index.ts's module header — even when an
 * entry's `rootSlug` happens to match a slug also present in tsl-ec.
 *
 * SECURITY: an intermediate is NOT a trust anchor. Adding one here can NEVER
 * make an untrusted TSA cert trusted — `validateTsaCertChain` still requires
 * the chain to terminate at a self-signed, non-placeholder ROOT present in
 * `manifest.ts`.
 */

import uanatacaCa1_2021Pem from './intermediates/uanataca-ca1-2021.pem?raw';
import uanatacaCa2_2021Pem from './intermediates/uanataca-ca2-2021.pem?raw';

export interface TsaTrustIntermediate {
  /** Short machine-readable slug. */
  slug: string;
  /** Common name of the subordinate CA (matches the TSA leaf's issuer CN). */
  commonName: string;
  /** Slug of the root (in manifest.ts) this intermediate ultimately chains to. */
  rootSlug: string;
  /** Full legal name of the TSA operator. */
  orgName: string;
  /** Raw PEM string — full BEGIN/END CERTIFICATE block. */
  pemContent: string;
  /** SHA-256 fingerprint of the DER-encoded certificate, lowercase hex, no colons. */
  fingerprintSha256: string;
  /** ISO 8601 date — notBefore. */
  validFrom: string;
  /** ISO 8601 date — notAfter. */
  validUntil: string;
  /** Provenance / notes. */
  notes?: string;
}

export const TSA_INTERMEDIATES: readonly TsaTrustIntermediate[] = [
  {
    slug: 'uanataca-ca2-2021',
    commonName: 'UANATACA CA2 2021',
    rootSlug: 'uanataca',
    orgName: 'UANATACA S.A.',
    pemContent: uanatacaCa2_2021Pem,
    fingerprintSha256: '15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a',
    validFrom: '2021-06-03',
    validUntil: '2034-06-03',
    notes:
      'Issuing CA of MINTEL\'s accredited TSA ("Sello de tiempo acreditado de MINTEL – ' +
      'TSU02", EKU id-kp-timeStamping critical, AKI C5:E7:33:25…). Same cert, byte for ' +
      "byte, as @firma-ec/tsl-ec's uanataca-ca2-2021.pem (which there issues signing " +
      'certs). Real case 2026-09-23: a UANATACA-signed contract carried a leaf-only ' +
      'MINTEL TSU02 token that failed with chain_invalid. openssl verify -purpose ' +
      'timestampsign: TSU02 → this CA → UANATACA ROOT 2016 OK.',
  },
  {
    slug: 'uanataca-ca1-2021',
    commonName: 'UANATACA CA1 2021',
    rootSlug: 'uanataca',
    orgName: 'UANATACA S.A.',
    pemContent: uanatacaCa1_2021Pem,
    fingerprintSha256: '9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a',
    validFrom: '2021-06-03',
    validUntil: '2034-06-03',
    notes:
      'Issuing CA for UANATACA RFC 3161 timestamps (subject CN "Sello de tiempo ' +
      'electrónico de UANATACA - TSU01", EKU id-kp-timeStamping critical) — distinct ' +
      'from the "UANATACA CA1/CA2 2016/2021" CAs in @firma-ec/tsl-ec, which issue ' +
      'end-entity SIGNING certs, not timestamps. Chains to "UANATACA ROOT 2016" (root ' +
      'slug "uanataca" in this package\'s manifest.ts). Extracted 2026-08-06 forensically ' +
      'from the RFC 3161 token embedded in a real signed contract (both signatures), then ' +
      "fetched authentically via the leaf's own AIA caIssuers URL " +
      '(https://web.uanataca.com/common/project/pdf/autoridad-certificacion/' +
      '07_subordinada-ca1-2021.cer) — AKI/SKI chain verified leaf → this intermediate → ' +
      'the already-trusted root byte-for-byte.',
  },
];
