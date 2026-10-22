import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
/**
 * El texto que lleva el QR de cada PDF firmado. Los usuarios pidieron que al
 * escanearlo se vea lo mismo que muestra el QR de la firma de Security Data /
 * FirmaEC: quién firmó, el DN completo del certificado, con qué se firmó y la
 * fecha, no solo un enlace. El enlace de verificación sigue dentro del texto
 * (los lectores de QR lo muestran pulsable) para no perder el deep-link `?h=`.
 *
 * Muestra real (QR decodificado de una estampa de Security Data, 2026-10-22):
 *   FIRMADO POR: <CN>\nRAZON: C=EC, O=…, OU=…, SERIALNUMBER=…, CN=…\n
 *   LOCALIZACION: Firmado digitalmente con <entidad>\n<url>\nFECHA: \n<ISO>
 */
import { describe, expect, it } from 'vitest';
import { parsePfx } from '../src/p12.js';
import {
  MIN_QR_MODULE_PT,
  buildQrPayload,
  fitQrPayload,
  formatIsoWithOffset,
  subjectDnFromDer,
} from '../src/qrPayload.js';

const FIX_DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PIN = 'test1234';

describe('formatIsoWithOffset', () => {
  it('imprime fecha local con milisegundos y desfase con dos puntos', () => {
    // 2026-10-21T14:26:04.492Z en Ecuador (UTC-5) = 09:26:04.492-05:00
    const d = new Date(Date.UTC(2026, 9, 21, 14, 26, 4, 492));
    expect(formatIsoWithOffset(d, -300)).toBe('2026-10-21T09:26:04.492-05:00');
  });
  it('desfase positivo y cero', () => {
    const d = new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 6));
    expect(formatIsoWithOffset(d, 0)).toBe('2026-01-02T03:04:05.006+00:00');
    expect(formatIsoWithOffset(d, 330)).toBe('2026-01-02T08:34:05.006+05:30');
  });
});

describe('buildQrPayload', () => {
  const base = {
    signerName: 'DIANA CAROLINA BENALCAZAR CHINACALLE',
    subjectDn:
      'C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=1723252472-161024133707, CN=DIANA CAROLINA BENALCAZAR CHINACALLE',
    verifyUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
    signingTime: new Date(Date.UTC(2026, 9, 21, 14, 26, 4, 492)),
    offsetMinutes: -300,
  };

  it('replica la estructura del QR de Security Data/FirmaEC, byte a byte', () => {
    expect(buildQrPayload(base)).toBe(
      'FIRMADO POR: DIANA CAROLINA BENALCAZAR CHINACALLE\n' +
        'RAZON: C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=1723252472-161024133707, CN=DIANA CAROLINA BENALCAZAR CHINACALLE\n' +
        'LOCALIZACION: Firmado digitalmente con firmar.ec\n' +
        'https://app.firmar.ec/#/verificar?h=abc123def456\n' +
        'FECHA: \n' +
        '2026-10-21T09:26:04.492-05:00',
    );
  });

  it('no deja saltos de línea ni caracteres de control dentro de un campo', () => {
    const p = buildQrPayload({ ...base, signerName: 'A\nB\u0000C', subjectDn: 'CN=X\r\nY' });
    expect(p.split('\n')).toHaveLength(6);
    const hasControl = [...p].some((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      return (code < 0x20 && code !== 0x0a) || code === 0x7f;
    });
    expect(hasControl).toBe(false);
  });

  it('con un DN vacío conserva la línea RAZON con el nombre como respaldo', () => {
    const p = buildQrPayload({ ...base, subjectDn: '' });
    expect(p).toContain('RAZON: CN=DIANA CAROLINA BENALCAZAR CHINACALLE\n');
  });

  it('no afirma que el documento o el certificado estén verificados o sean válidos', () => {
    expect(buildQrPayload(base)).not.toMatch(/verificad|v[aá]lid|aprobad|garantiz/i);
  });
});

describe('subjectDnFromDer', () => {
  it('lee el DN del certificado en el MISMO orden en que viene en el certificado', async () => {
    const pfx = await parsePfx(
      new Uint8Array(readFileSync(join(FIX_DIR, 'rsa2048-valid.p12'))),
      PIN,
    );
    const dn = subjectDnFromDer(pfx.signingCert.der);
    // El certificado de prueba guarda CN primero; el de Security Data guarda C primero.
    // Se respeta lo que trae cada uno: nada de reordenar.
    expect(dn.startsWith('CN=Test Signer RSA-2048, C=EC')).toBe(true);
    expect(dn.split(', ').every((part) => /^[A-Za-z0-9.]+=./.test(part))).toBe(true);
  });
  it('un DER inválido devuelve cadena vacía, sin lanzar', () => {
    expect(subjectDnFromDer(new Uint8Array([1, 2, 3]))).toBe('');
  });
});

describe('fitQrPayload: el QR tiene que seguir siendo legible y la firma no puede abortar', () => {
  const sampleDn =
    'C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=1723252472-161024133707, CN=DIANA CAROLINA BENALCAZAR CHINACALLE';
  const input = (over: Partial<Parameters<typeof buildQrPayload>[0]> = {}) => ({
    signerName: 'DIANA CAROLINA BENALCAZAR CHINACALLE',
    subjectDn: sampleDn,
    verifyUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
    signingTime: new Date(Date.UTC(2026, 9, 21, 14, 26, 4, 492)),
    offsetMinutes: -300,
    ...over,
  });
  const sizeOf = (text: string) => QRCode.create(text, { errorCorrectionLevel: 'M' }).modules.size;

  it('con el DN de la muestra y 60 pt usa el texto completo', () => {
    expect(fitQrPayload(input(), 60)).toBe(buildQrPayload(input()));
  });

  it('un DN largo (con tildes) pasa a CN + SERIALNUMBER y sigue con el texto de 6 líneas', () => {
    const longDn = `${sampleDn}, OU=${'UNIDAD DE CERTIFICACIÓN Ñ '.repeat(20)}`;
    const out = fitQrPayload(input({ subjectDn: longDn }), 60);
    expect(out).not.toBe(buildQrPayload(input({ subjectDn: longDn })));
    expect(out).toContain(
      'RAZON: SERIALNUMBER=1723252472-161024133707, CN=DIANA CAROLINA BENALCAZAR CHINACALLE\n',
    );
    expect(out.split('\n')).toHaveLength(6);
    expect(sizeOf(out)).toBeLessThanOrEqual(Math.floor(60 / MIN_QR_MODULE_PT));
  });

  it('un texto que no cabe en NINGUNA versión del QR vuelve a la URL sola, sin lanzar', () => {
    const out = fitQrPayload(input({ signerName: 'Ñ'.repeat(3000), subjectDn: '' }), 60);
    expect(out).toBe('https://app.firmar.ec/#/verificar?h=abc123def456');
  });

  it('un área más pequeña (40 pt) nunca produce módulos por debajo del mínimo legible', () => {
    const out = fitQrPayload(input(), 40);
    expect(sizeOf(out)).toBeLessThanOrEqual(Math.floor(40 / MIN_QR_MODULE_PT));
  });
});
