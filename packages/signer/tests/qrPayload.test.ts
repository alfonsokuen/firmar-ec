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
    signerName: 'LUCIA FERNANDA TORRES MENDOZA SUAREZ',
    subjectDn:
      'C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=0000000000-000000000000, CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ',
    verifyUrl: 'https://app.firmar.ec/#/verificar?h=abc123def456',
    signingTime: new Date(Date.UTC(2026, 9, 21, 14, 26, 4, 492)),
    offsetMinutes: -300,
  };

  it('replica la estructura del QR de Security Data/FirmaEC, byte a byte', () => {
    expect(buildQrPayload(base)).toBe(
      'FIRMADO POR: LUCIA FERNANDA TORRES MENDOZA SUAREZ\n' +
        'RAZON: C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=0000000000-000000000000, CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ\n' +
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
    expect(p).toContain('RAZON: CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ\n');
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
    'C=EC, O=SECURITY DATA S.A. 2, OU=ENTIDAD DE CERTIFICACION DE INFORMACION, SERIALNUMBER=0000000000-000000000000, CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ';
  const input = (over: Partial<Parameters<typeof buildQrPayload>[0]> = {}) => ({
    signerName: 'LUCIA FERNANDA TORRES MENDOZA SUAREZ',
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
      'RAZON: SERIALNUMBER=0000000000-000000000000, CN=LUCIA FERNANDA TORRES MENDOZA SUAREZ\n',
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

describe('subjectDnFromDer: atributos con nombre legible (cargo e identificador de organización)', () => {
  // Certificado real de la ECI de Security Data/BCE: el cargo (2.5.4.12) y el identificador de la
  // organización (2.5.4.97) salían con su número y el teléfono los subrayaba como si fueran enlaces.
  it('2.5.4.12 sale como title y 2.5.4.97 como organizationIdentifier', async () => {
    const forge = (await import('node-forge')).default;
    const keys = forge.pki.rsa.generateKeyPair(1024);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date(Date.now() - 86_400_000);
    cert.validity.notAfter = new Date(Date.now() + 86_400_000);
    const subject = [
      { shortName: 'C', value: 'EC' },
      { name: 'organizationName', value: 'EMPRESA EJEMPLO S.A.S.' },
      { type: '2.5.4.12', value: 'GERENTE GENERAL' },
      { type: '2.5.4.4', value: 'APELLIDO PRUEBA' },
      { type: '2.5.4.42', value: 'NOMBRE' },
      { name: 'serialNumber', value: 'IDCEC-0000000000' },
      { shortName: 'CN', value: 'NOMBRE APELLIDO PRUEBA' },
      { type: '2.5.4.97', value: 'VATEC-0000000000001' },
    ];
    cert.setSubject(subject);
    cert.setIssuer(subject);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    const der = Uint8Array.from(Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary'));
    expect(subjectDnFromDer(der)).toBe(
      'C=EC, O=EMPRESA EJEMPLO S.A.S., title=GERENTE GENERAL, SN=APELLIDO PRUEBA, GN=NOMBRE, SERIALNUMBER=IDCEC-0000000000, CN=NOMBRE APELLIDO PRUEBA, organizationIdentifier=VATEC-0000000000001',
    );
  });
});
