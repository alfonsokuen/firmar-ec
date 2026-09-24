/**
 * OCSP KAT against real ARCOTEL-accredited ACE responders.
 *
 * Captured 2026-05-10 from:
 *   - ocspgw.securitydata.net.ec (SECURITY DATA S.A. 2 SubCA-2)
 *   - ocsp.argosdata.com.ec      (ArgosData CA 1 - SHA256)
 *
 * Both responses status=good, captured via `openssl ocsp` against leaf certs
 * extracted from packages/verifier/tests/fixtures/eci-real-*.pdf.
 *
 * If issuer DER is absent, tests SKIP with rationale.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { parseOcspResponse } from '../src/ocsp/response';
import type { ParsedCert } from '../src/types';

const FX_DIR = resolve(__dirname, '__fixtures__');

function toAB(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < u.length; i++) out += (u[i] ?? 0).toString(16).padStart(2, '0');
  return out;
}

/** Read the CertID's serial straight off the wire, bypassing the module
 * under test, purely to supply the now-mandatory `expected` param for these
 * raw captured fixtures (we don't have the leaf cert on hand independently). */
function readEchoedSerialHex(der: Uint8Array): string {
  const asn = asn1js.fromBER(toAB(der));
  const ocspResp = new pkijs.OCSPResponse({ schema: asn.result });
  const respBytes = ocspResp.responseBytes;
  if (!respBytes) throw new Error('no responseBytes in KAT fixture');
  const innerHex = (respBytes.response.valueBlock as { valueHex: ArrayBuffer }).valueHex;
  const basicAsn = asn1js.fromBER(innerHex);
  const basic = new pkijs.BasicOCSPResponse({ schema: basicAsn.result });
  const single = basic.tbsResponseData.responses[0];
  if (!single) throw new Error('no SingleResponse in KAT fixture');
  return bufToHex((single.certID.serialNumber.valueBlock as { valueHex: ArrayBuffer }).valueHex);
}

function loadDer(name: string): Uint8Array | null {
  const p = resolve(FX_DIR, name);
  if (!existsSync(p)) return null;
  return new Uint8Array(readFileSync(p));
}

const SD_ISSUER = loadDer('securitydata-subca2-issuer.der');
const SD_OCSP = loadDer('securitydata-subca2-ocsp-2026-05-10.der');
const AR_ISSUER = loadDer('argosdata-ca1-issuer.der');
const AR_OCSP = loadDer('argosdata-ace-ocsp-2026-05-10.der');

const HAVE_SD = SD_ISSUER !== null && SD_OCSP !== null;
const HAVE_AR = AR_ISSUER !== null && AR_OCSP !== null;

function fakeIssuer(der: Uint8Array, cn: string): ParsedCert {
  return {
    subjectCN: cn,
    issuerCN: null,
    der,
    notBefore: new Date(0),
    notAfter: new Date(2099, 0, 1),
  };
}

describe('OCSP KAT — ARCOTEL ACEs (real responders)', () => {
  it.skipIf(!HAVE_SD)('SECURITY DATA SubCA-2 OCSP parses and reports good', async () => {
    if (!SD_OCSP || !SD_ISSUER) return;
    const parsed = await parseOcspResponse(
      SD_OCSP,
      fakeIssuer(SD_ISSUER, 'SubCA-2 Security Data'),
      {
        serialHex: readEchoedSerialHex(SD_OCSP),
      },
    );
    expect(parsed.certStatus).toBe('good');
    expect(parsed.serialHex.length).toBeGreaterThan(0);
    // The live verifier now rejects unauthenticated responses, so a real
    // ACE response must authenticate, not merely parse.
    expect(parsed.signatureValid, parsed.signatureDetail).toBe(true);
  });

  // Regression (defect this branch fixes): ArgosData's ACE responder signs
  // directly with the CA key and attaches NO certs[] — pkijs's own
  // `BasicOCSPResponse.verify()` throws "No certificates attached" on this
  // shape instead of falling back to the issuer, so `signatureValid` used to
  // come back false for a perfectly legitimate response. This is a measured,
  // LIVE availability bug (2026-07-30), not a hypothetical.
  it.skipIf(!HAVE_AR)(
    'ArgosData CA 1 OCSP (issuer signs directly, no certs[]) parses, reports good, signatureValid=true',
    async () => {
      if (!AR_OCSP || !AR_ISSUER) return;
      const parsed = await parseOcspResponse(
        AR_OCSP,
        fakeIssuer(AR_ISSUER, 'ArgosData CA 1 - SHA256'),
        { serialHex: readEchoedSerialHex(AR_OCSP) },
      );
      expect(parsed.certStatus).toBe('good');
      expect(parsed.serialHex.length).toBeGreaterThan(0);
      expect(parsed.signatureValid).toBe(true);
    },
  );

  it.runIf(!HAVE_SD && !HAVE_AR)('SKIP rationale: ARCOTEL ACE fixtures absent', () => {
    expect(true).toBe(true);
  });
});

// Live answers captured 2026-09-24 from each ACE's own responder (one per
// issuing CA, queried with a real certificate from a signed PDF). Locks the
// strict responder authentication (RFC 6960 §4.2.2.2) against the real
// responders: five of the six answer through a delegated responder cert.
const LIVE_2026_09_24 = [
  ['AC Banco Central del Ecuador', 'bce-ac'],
  ['Security Data SubCA-2', 'securitydata-subca2-live'],
  ['iCert-EC (Consejo de la Judicatura)', 'icert-ec'],
  ['UANATACA CA2 2016', 'uanataca-ca2-2016'],
  ['UANATACA CA2 2021', 'uanataca-ca2-2021'],
  ['ArgosData CA 1', 'argosdata-ca1-live'],
] as const;

describe('OCSP KAT — live ACE responders, 2026-09-24', () => {
  for (const [name, slug] of LIVE_2026_09_24) {
    const ocsp = loadDer(`${slug}-ocsp-2026-09-24.der`);
    const issuer = loadDer(`${slug}-issuer.der`);
    it.skipIf(!ocsp || !issuer)(`${name}: authenticates and reports good`, async () => {
      if (!ocsp || !issuer) return;
      const parsed = await parseOcspResponse(ocsp, fakeIssuer(issuer, name), {
        serialHex: readEchoedSerialHex(ocsp),
      });
      expect(parsed.signatureValid, parsed.signatureDetail).toBe(true);
      expect(parsed.certStatus).toBe('good');
    });
  }
});
