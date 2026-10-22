/**
 * Texto que lleva el QR de cada PDF firmado.
 *
 * Los usuarios pidieron que al escanear el QR se vea lo mismo que muestra el QR
 * de la firma de Security Data / FirmaEC: quién firmó, el DN completo del
 * certificado, con qué se firmó y cuándo, no solo un enlace. El enlace de
 * verificación (`buildVerifyQrUrl`) sigue dentro del texto, en su propia línea:
 * los lectores de QR lo muestran pulsable y se conserva el deep-link `?h=`.
 *
 * Este texto NO verifica nada y no debe decir que lo hace: es lo que el firmante
 * declara al firmar. La verificación criptográfica la hace el verificador.
 */
import { decodeAsn1DirectoryString, parseCertificateDer } from '@firma-ec/crypto-core';

/** Etiqueta de la línea LOCALIZACION; el nombre del producto, no una entidad certificadora. */
export const QR_SIGNED_WITH = 'firmar.ec';

/** Nombres cortos de atributos X.500; cualquier otro sale como su OID con puntos. */
const DN_SHORT_NAMES: Record<string, string> = {
  '2.5.4.6': 'C',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.3': 'CN',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.4': 'SN',
  '2.5.4.42': 'GN',
};

/** Un campo del QR ocupa UNA línea: sin saltos ni caracteres de control. */
function oneLine(value: string): string {
  let out = '';
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f ? ' ' : ch;
  }
  return out.replace(/\s{2,}/g, ' ').trim();
}

const pad = (n: number, width = 2) => String(Math.abs(Math.trunc(n))).padStart(width, '0');

/**
 * `2026-10-21T09:26:04.492-05:00`: hora local del firmante con milisegundos y
 * desfase con dos puntos (el formato que imprime el QR de referencia).
 * `offsetMinutes` es el desfase respecto a UTC (Ecuador: -300).
 */
export function formatIsoWithOffset(date: Date, offsetMinutes: number): string {
  const local = new Date(date.getTime() + offsetMinutes * 60_000);
  const sign = offsetMinutes < 0 ? '-' : '+';
  return (
    `${pad(local.getUTCFullYear(), 4)}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}` +
    `T${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}:${pad(local.getUTCSeconds())}` +
    `.${pad(local.getUTCMilliseconds(), 3)}` +
    `${sign}${pad(offsetMinutes / 60)}:${pad(Math.abs(offsetMinutes) % 60)}`
  );
}

/**
 * DN del sujeto en el orden del certificado (`C=EC, O=…, OU=…, SERIALNUMBER=…,
 * CN=…`). Cadena vacía si el DER no se puede leer: el QR sale igual, con el
 * nombre como respaldo, y la firma no se aborta por un dato opcional.
 */
export function subjectDnFromDer(der: Uint8Array): string {
  try {
    const cert = parseCertificateDer(der);
    return cert.subject.typesAndValues
      .map(
        (tv) =>
          `${DN_SHORT_NAMES[tv.type] ?? tv.type}=${oneLine(decodeAsn1DirectoryString(tv.value))}`,
      )
      .join(', ');
  } catch {
    return '';
  }
}

export interface QrPayloadInput {
  /** CN del certificado de firma. */
  signerName: string;
  /** Salida de {@link subjectDnFromDer}; vacía si no se pudo leer. */
  subjectDn: string;
  /** URL de verificación con el hash del PDF (`buildVerifyQrUrl`). */
  verifyUrl: string;
  signingTime: Date;
  /** Desfase respecto a UTC en minutos; por defecto el del equipo que firma. */
  offsetMinutes?: number | undefined;
}

export function buildQrPayload(input: QrPayloadInput): string {
  const name = oneLine(input.signerName);
  const dn = oneLine(input.subjectDn) || `CN=${name}`;
  const offset = input.offsetMinutes ?? -input.signingTime.getTimezoneOffset();
  return [
    `FIRMADO POR: ${name}`,
    `RAZON: ${dn}`,
    `LOCALIZACION: Firmado digitalmente con ${QR_SIGNED_WITH}`,
    oneLine(input.verifyUrl),
    'FECHA: ',
    formatIsoWithOffset(input.signingTime, offset),
  ].join('\n');
}
