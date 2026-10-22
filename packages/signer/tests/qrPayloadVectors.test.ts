/**
 * Vectores de referencia del texto del QR de firma. Los comparten los portes a
 * otros lenguajes (3tap, Odoo, ingreso express): cada uno debe producir EXACTAMENTE
 * `expected` para cada caso. Regenerar solo a propósito:
 *   QR_VECTORS_WRITE=1 pnpm --filter @firma-ec/signer exec vitest run tests/qrPayloadVectors.test.ts
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { fitQrPayload } from '../src/qrPayload.js';

const FILE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'qr-payload-vectors.json');
const SD_DN =
  'C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=0000000000-000000000000, CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ';
const URL = 'https://app.firmar.ec/#/verificar?h=abc123def456';

interface Case {
  name: string;
  signerName: string;
  subjectDn: string;
  verifyUrl: string;
  signingTimeUtc: string;
  offsetMinutes: number;
  areaPt: number;
}

const base = {
  verifyUrl: URL,
  signingTimeUtc: '2026-10-21T14:26:04.492Z',
  offsetMinutes: -300,
  areaPt: 60,
};

const CASES: Case[] = [
  { name: 'security-data-sample', signerName: 'LUCIA FERNANDA TORRES MENDOZA SUAREZ', subjectDn: SD_DN, ...base },
  { name: 'test-fixture-short-dn', signerName: 'Test Signer RSA-2048', subjectDn: 'CN=Test Signer RSA-2048, C=EC, O=firma-ec test fixture', ...base },
  {
    name: 'long-dn-with-accents-falls-back-to-serial-and-cn',
    signerName: 'MARÍA JOSÉ NÚÑEZ PEÑAHERRERA DE LA TORRE',
    subjectDn: `C=EC, O=ENTIDAD DE CERTIFICACIÓN Y SERVICIOS RELACIONADOS DEL ECUADOR SOCIEDAD ANÓNIMA, OU=${'UNIDAD DE CERTIFICACIÓN Ñ '.repeat(20)}, SERIALNUMBER=0000000000-000000000000, CN=MARÍA JOSÉ NÚÑEZ PEÑAHERRERA DE LA TORRE`,
    ...base,
  },
  { name: 'too-big-falls-back-to-url-only', signerName: 'Ñ'.repeat(3000), subjectDn: '', ...base },
  { name: 'small-area-40pt', signerName: 'LUCIA FERNANDA TORRES MENDOZA SUAREZ', subjectDn: SD_DN, ...base, areaPt: 40 },
  { name: 'offset-plus-0530', signerName: 'A B', subjectDn: 'CN=A B', ...base, signingTimeUtc: '2026-01-02T03:04:05.006Z', offsetMinutes: 330 },
  { name: 'offset-zero', signerName: 'A B', subjectDn: 'CN=A B', ...base, signingTimeUtc: '2026-01-02T03:04:05.006Z', offsetMinutes: 0 },
  { name: 'control-chars-and-newlines-are-flattened', signerName: 'A\nB\u0000C', subjectDn: 'CN=X\r\nY', ...base },
  { name: 'empty-dn-uses-cn-fallback', signerName: 'LUCIA FERNANDA TORRES MENDOZA SUAREZ', subjectDn: '', ...base },
];

const compute = (c: Case) =>
  fitQrPayload(
    {
      signerName: c.signerName,
      subjectDn: c.subjectDn,
      verifyUrl: c.verifyUrl,
      signingTime: new Date(c.signingTimeUtc),
      offsetMinutes: c.offsetMinutes,
    },
    c.areaPt,
  );

describe('vectores del texto del QR (compartidos con los portes a Python)', () => {
  it('el fichero de vectores coincide con la implementación', () => {
    const fresh = CASES.map((c) => ({ ...c, expected: compute(c) }));
    if (process.env.QR_VECTORS_WRITE === '1') {
      writeFileSync(FILE, `${JSON.stringify({ version: 1, minModulePt: 0.8, cases: fresh }, null, 2)}\n`);
    }
    const onDisk = JSON.parse(readFileSync(FILE, 'utf-8')) as { cases: unknown };
    expect(onDisk.cases).toEqual(fresh);
  });

  it('cubre las cuatro ramas: completo, DN reducido, solo URL y área pequeña', () => {
    const outs = CASES.map(compute);
    expect(outs.some((o) => o.includes('RAZON: C=EC, O=SECURITY DATA'))).toBe(true);
    expect(outs.some((o) => o.includes('RAZON: SERIALNUMBER=0000000000-000000000000, CN=MARÍA'))).toBe(true);
    expect(outs).toContain(URL);
  });
});
