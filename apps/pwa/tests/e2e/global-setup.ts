/**
 * global-setup.ts — generates an ephemeral RSA-2048 self-signed .p12 fixture
 * for the "modo guiado" F1 spike (real-signing e2e coverage).
 *
 * Why generated at test-run time instead of committed: this is a throwaway
 * signing key with a well-known password. It carries zero real-world value
 * (self-signed, CN "Prueba E2E", not chained to any CA/TSL), but committing
 * *any* .p12 to git is unnecessary residual risk — generating it fresh each
 * run costs <50ms and leaves nothing in history to ever worry about.
 *
 * Mirrors packages/signer/scripts/gen-test-p12.ts (same node-forge recipe,
 * same fixture shape: RSA-2048, PBES2+AES-256 PKCS#12, PIN "test1234").
 * `node-forge` does NOT resolve from the repo root or transitively through
 * @firma-ec/signer's public API — it had to be added as a devDependency of
 * @firma-ec/pwa itself (see apps/pwa/package.json) for this script to import it.
 *
 * @see apps/pwa/playwright.config.ts (globalSetup wiring)
 * @see apps/pwa/tests/e2e/spike-sign.spec.ts (consumer)
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import forge from 'node-forge';
import { E2E_REP_LEGAL_ATTRS, E2E_REP_LEGAL_CN } from './helpers/rep-legal-fixture';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, 'fixtures', 'generated');
const OUT_FILE = join(OUT_DIR, 'test-signer.p12');
const AIA_P12_FILE = join(OUT_DIR, 'test-signer-aia-bundle-miss.p12');
const AIA_INTERMEDIATE_PEM_FILE = join(OUT_DIR, 'test-aia-intermediate.pem');
const REP_LEGAL_P12_FILE = join(OUT_DIR, 'test-representante-legal.p12');

/**
 * PIN for the generated fixture. Intentionally a fixed, non-secret literal —
 * this key is regenerated from scratch on every test run, is never chained to
 * any real trust anchor, and never leaves the local machine / CI runner.
 * Matches the PIN used by the sibling fixtures in packages/signer/tests/fixtures/.
 */
const E2E_TEST_P12_PIN = 'test1234';

function generateSelfSignedP12(): Buffer {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = `01${Math.floor(Math.random() * 1e9)
    .toString(16)
    .padStart(8, '0')}`;
  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 60_000);
  cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000);
  const attrs = [
    { name: 'commonName', value: 'Prueba E2E' },
    { name: 'countryName', value: 'EC' },
    { name: 'organizationName', value: 'firma-ec e2e spike (modo guiado F1)' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true, codeSigning: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], E2E_TEST_P12_PIN, {
    algorithm: 'aes256',
    useMac: true,
    count: 2048,
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(p12Der, 'binary');
}

/**
 * F1 E2E fixtures — real-browser coverage of the AIA caIssuers fallback
 * (see apps/pwa/tests/e2e/aia-fallback.spec.ts).
 *
 * WHY a leaf-only .p12 whose AIA URL is UANATACA's REAL subordinate1.crt
 * endpoint string: `ARCOTEL_PROXY_MAP` (packages/ltv-validation/src/proxy.ts)
 * rewrites URLs by EXACT string match, allowlist-only (anti-SSRF). Reusing
 * that exact key means the leaf naturally routes through the real
 * `/api/aia/uanataca` same-origin path the production Caddyfile also
 * exposes — the E2E exercises the REAL proxy-routing logic, not a shortcut
 * around it. `e2eMockAia` in vite.config.ts intercepts that same path in dev
 * mode only (E2E_MOCK_AIA=1) so the test never touches the real UANATACA
 * network.
 *
 * The intermediate is deliberately SELF-signed (not chained to any bundled
 * root): this app's trust bundle can only be extended by shipping a new
 * @firma-ec/tsl-ec release, never by a live AIA response (see
 * chainIntermediates.ts's HIGH-B fix) — a real production root's private key
 * isn't something a test fixture can ever legitimately hold. So AIA
 * resolving this intermediate is expected to still leave `chainComplete:
 * false` (the intermediate embeds, but its own issuer is untrusted) — that
 * is exactly the scenario the E2E's `chain_incomplete` UI assertions cover.
 */
const AIA_TEST_INTERMEDIATE_AIA_URL =
  'http://www.uanataca.com/public/download/tsp_certificates/subordinate1.crt';

const OID_AIA = '1.3.6.1.5.5.7.1.1';
const OID_AD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2';

/** Build the extnValue OCTET STRING contents for an AIA extension with a
 *  single caIssuers AccessDescription (RFC 5280 §4.2.2.1), using forge's own
 *  ASN.1 module — avoids adding asn1js as a second DER library just for this
 *  script (node-forge is already a devDependency here). */
function buildCaIssuersAiaExtnValueDer(url: string): string {
  const accessLocation = forge.asn1.create(
    forge.asn1.Class.CONTEXT_SPECIFIC,
    6, // [6] IMPLICIT IA5String (uniformResourceIdentifier)
    false,
    url,
  );
  const accessDescription = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer(OID_AD_CA_ISSUERS).getBytes(),
      ),
      accessLocation,
    ],
  );
  const aia = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    accessDescription,
  ]);
  return forge.asn1.toDer(aia).getBytes();
}

/**
 * Generates a leaf-only .p12 (bundle-miss scenario: the intermediate is NOT
 * included) whose leaf carries a caIssuers AIA extension pointing at
 * {@link AIA_TEST_INTERMEDIATE_AIA_URL}, signed by a synthetic self-signed
 * intermediate CA. Returns both the .p12 bytes and the intermediate's PEM
 * (served by `e2eMockAia`'s dev-only middleware at `/api/aia/uanataca`).
 */
function generateAiaTestChain(): { p12: Buffer; intermediatePem: string } {
  const interKeys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const interCert = forge.pki.createCertificate();
  interCert.publicKey = interKeys.publicKey;
  interCert.serialNumber = '01';
  const now = new Date();
  interCert.validity.notBefore = new Date(now.getTime() - 2 * 365 * 24 * 3600 * 1000);
  interCert.validity.notAfter = new Date(now.getTime() + 8 * 365 * 24 * 3600 * 1000);
  const interAttrs = [
    { name: 'commonName', value: 'Synthetic E2E CA (untrusted)' },
    { name: 'countryName', value: 'EC' },
  ];
  interCert.setSubject(interAttrs);
  interCert.setIssuer(interAttrs); // self-signed
  interCert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true },
  ]);
  interCert.sign(interKeys.privateKey, forge.md.sha256.create());

  const leafKeys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafCert = forge.pki.createCertificate();
  leafCert.publicKey = leafKeys.publicKey;
  leafCert.serialNumber = `01${Math.floor(Math.random() * 1e9)
    .toString(16)
    .padStart(8, '0')}`;
  leafCert.validity.notBefore = new Date(now.getTime() - 60_000);
  leafCert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000);
  leafCert.setSubject([
    { name: 'commonName', value: 'Prueba E2E AIA' },
    { name: 'countryName', value: 'EC' },
  ]);
  leafCert.setIssuer(interCert.subject.attributes);
  leafCert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true, codeSigning: true },
    {
      id: OID_AIA,
      critical: false,
      value: buildCaIssuersAiaExtnValueDer(AIA_TEST_INTERMEDIATE_AIA_URL),
    } as unknown as forge.pki.CertificateExtension,
  ]);
  leafCert.sign(interKeys.privateKey, forge.md.sha256.create());

  // Leaf-only — the intermediate is deliberately NOT included, so the signer
  // has no choice but to try the bundle (miss) then the AIA fallback.
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(leafKeys.privateKey, [leafCert], E2E_TEST_P12_PIN, {
    algorithm: 'aes256',
    useMac: true,
    count: 2048,
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return {
    p12: Buffer.from(p12Der, 'binary'),
    intermediatePem: forge.pki.certificateToPem(interCert),
  };
}

/**
 * ACE arc of ArgosData. Every accredited CA publishes the holder's identity
 * under its own private arc reusing the same suffixes — `.5` cargo, `.10`
 * razón social, `.11` the RUC of the company. See packages/crypto-core/src/ec-identity.ts.
 */
const ACE_ARC = '1.3.6.1.4.1.59198.3';

/** DER of a UTF8String — the encoding every ACE uses for these attributes. */
function derUtf8(value: string): string {
  return forge.asn1
    .toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, value))
    .getBytes();
}

/**
 * Legal-representative .p12 for the "Validar certificado" e2e.
 *
 * Synthetic on purpose: a REAL legal-representative certificate carries the
 * cédula of a person and the RUC of a live company, and no such file may enter
 * this repository — not even to prove the feature works. The identity below is
 * invented (cédula 1700000001 passes the mod-10 check but belongs to nobody).
 *
 * Self-signed, so the page reports it as not accredited — irrelevant here: the
 * assertion is that the three fields get RENDERED, which is exactly what was
 * missing before and what a unit test on the parser cannot prove.
 */
function generateRepresentanteLegalP12(): Buffer {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = `01${Math.floor(Math.random() * 1e9)
    .toString(16)
    .padStart(8, '0')}`;
  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 60_000);
  cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000);

  const attrs = [
    { name: 'commonName', value: E2E_REP_LEGAL_CN },
    { name: 'countryName', value: 'EC' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
    ...Object.entries(E2E_REP_LEGAL_ATTRS).map(
      (entry) =>
        ({
          id: `${ACE_ARC}.${entry[0]}`,
          critical: false,
          value: derUtf8(entry[1]),
        }) as unknown as forge.pki.CertificateExtension,
    ),
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], E2E_TEST_P12_PIN, {
    algorithm: 'aes256',
    useMac: true,
    count: 2048,
  });
  return Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary');
}

export default function globalSetup(): void {
  if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
  const p12 = generateSelfSignedP12();
  writeFileSync(OUT_FILE, p12);

  const aiaChain = generateAiaTestChain();
  writeFileSync(AIA_P12_FILE, aiaChain.p12);
  writeFileSync(AIA_INTERMEDIATE_PEM_FILE, aiaChain.intermediatePem);

  const repLegal = generateRepresentanteLegalP12();
  writeFileSync(REP_LEGAL_P12_FILE, repLegal);

  // globalSetup runs in plain Node before the test runner reporter attaches;
  // console.log is the only visibility into fixture generation (mirrors the
  // convention in packages/signer/scripts/gen-test-p12.ts).
  // biome-ignore lint/suspicious/noConsole: intentional — see comment above.
  console.log(`[global-setup] generated ephemeral e2e .p12 → ${OUT_FILE} (${p12.length} bytes)`);
  // biome-ignore lint/suspicious/noConsole: intentional — see comment above.
  console.log(
    `[global-setup] generated F1 AIA leaf-only .p12 → ${AIA_P12_FILE} (${aiaChain.p12.length} bytes)`,
  );
  // biome-ignore lint/suspicious/noConsole: intentional — see comment above.
  console.log(
    `[global-setup] generated legal-representative .p12 → ${REP_LEGAL_P12_FILE} (${repLegal.length} bytes)`,
  );
}
