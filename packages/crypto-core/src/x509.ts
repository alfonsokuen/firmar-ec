import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { oidName } from './oids';

export function parseCertificateDer(der: Uint8Array): Certificate {
  const asn = fromBER(der.buffer as ArrayBuffer);
  if (asn.offset === -1) throw new Error('ASN.1 parse failed');
  return new Certificate({ schema: asn.result });
}

export function parseCertificatePem(pem: string): Certificate {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return parseCertificateDer(der);
}

export interface SubjectInfo {
  cn?: string | undefined;
  o?: string | undefined;
  ou?: string | undefined;
  c?: string | undefined;
  serialNumber?: string | undefined;
  raw: Record<string, string>;
}

/**
 * Tipos ASN.1 de cadena que asn1js (y node-forge) decodifican BYTE A BYTE,
 * como Latin-1. Una CA que meta UTF-8 dentro de uno de ellos —lo hacen— deja
 * la Ñ como `Ã` + U+0091, y ese carácter de control tumba luego al codificador
 * WinAnsi de la estampa. UTF8String (12), BMPString (30) y UniversalString
 * (28) NO están: asn1js ya los decodifica bien y no hay nada que reparar.
 */
const BYTE_PER_CHAR_STRING_TAGS: ReadonlySet<number> = new Set([
  19, // PrintableString
  20, // TeletexString (T61String)
  22, // IA5String
  26, // VisibleString
  27, // GeneralString
]);

/**
 * ¿Es `tag` (número de etiqueta universal ASN.1) un tipo de cadena que los
 * parsers leen byte a byte? Es la ÚNICA lista positiva: la usa asn1js aquí y
 * node-forge en el signer, para que las dos rutas reparen exactamente lo mismo
 * (un BMPString, por ejemplo, no debe pasar por la reparación en ninguna).
 */
export function isByteStringAsn1Tag(tag: number | undefined): boolean {
  return typeof tag === 'number' && BYTE_PER_CHAR_STRING_TAGS.has(tag);
}

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Repara una cadena que era UTF-8 y se decodificó como Latin-1 (un carácter
 * por byte). Solo actúa si TODOS los caracteres caben en un byte, alguno es
 * ≥ 0x80 y la secuencia de bytes es UTF-8 válido; si no, devuelve la cadena
 * tal cual. Un Latin-1 auténtico (`Ñ` = 0xD1 suelto) no forma UTF-8 válido y
 * queda intacto.
 *
 * Límite conocido: inferir la codificación solo por validez UTF-8 es ambiguo
 * para un Latin-1 auténtico cuya secuencia TAMBIÉN sea UTF-8 válido — `Â£`
 * (C2 A3) se convierte en `£`. Eso exige un carácter de C2–DF seguido de uno
 * de 80–BF, combinación que no aparece en nombres ni razones sociales reales;
 * en los DN ecuatorianos el error en sentido contrario (UTF-8 metido en un
 * TeletexString) sí ocurre. Se asume el sesgo hacia UTF-8 a sabiendas.
 */
export function repairUtf8DecodedAsLatin1(s: string): string {
  let hasHighByte = false;
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp > 0xff) return s;
    if (cp >= 0x80) hasHighByte = true;
    bytes[i] = cp;
  }
  if (!hasHighByte) return s;
  try {
    return STRICT_UTF8.decode(bytes);
  } catch {
    return s;
  }
}

/**
 * Extract the raw string value from an asn1js value object.
 *
 * asn1js's `toString()` returns a debug-friendly representation like
 * `UTF8String : 'BEATRIZ DE LOURDES VALENCIA CACERES'` which is NOT what we
 * want for display. The actual string content lives at `valueBlock.value`
 * (for character string types: UTF8String, PrintableString, IA5String,
 * TeletexString, BMPString, etc.). Fall back to `toString()` only if the
 * structure is unexpected.
 *
 * Para los tipos byte-a-byte se pasa por {@link repairUtf8DecodedAsLatin1}.
 * Es la puerta por la que entran el sujeto y el emisor que se MUESTRAN y se
 * ESTAMPAN (`subjectInfo`/`issuerInfo` aquí, las dos lecturas del CN en el
 * signer). Otras lecturas de `valueBlock.value` (tsa-trust, tsa-client, OCSP)
 * comparan entre sí nombres ASCII de la TSL y no pasan por aquí a propósito.
 */
export function decodeAsn1DirectoryString(v: unknown): string {
  // pkijs/asn1js typing limitation
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  const block = v as any;
  const vb = block?.valueBlock?.value;
  if (typeof vb === 'string') {
    return isByteStringAsn1Tag(block?.idBlock?.tagNumber) ? repairUtf8DecodedAsLatin1(vb) : vb;
  }
  // Defensive fallback: strip the asn1js debug prefix if it sneaks in
  const s = String(v);
  const m = /^\w+\s*:\s*'(.*)'$/s.exec(s);
  return m?.[1] ?? s;
}

export function subjectInfo(cert: Certificate): SubjectInfo {
  const raw: Record<string, string> = {};
  for (const tv of cert.subject.typesAndValues) {
    raw[oidName(tv.type)] = decodeAsn1DirectoryString(tv.value);
  }
  return {
    cn: raw['CN'],
    o: raw['O'],
    ou: raw['OU'],
    c: raw['C'],
    serialNumber: raw['serialNumber'],
    raw,
  };
}

/** Extract issuer fields from a Certificate (mirrors subjectInfo but reads cert.issuer). */
export function issuerInfo(cert: Certificate): SubjectInfo {
  const raw: Record<string, string> = {};
  for (const tv of cert.issuer.typesAndValues) {
    raw[oidName(tv.type)] = decodeAsn1DirectoryString(tv.value);
  }
  return {
    cn: raw['CN'],
    o: raw['O'],
    ou: raw['OU'],
    c: raw['C'],
    serialNumber: raw['serialNumber'],
    raw,
  };
}

export function isWithinValidity(cert: Certificate, at: Date): boolean {
  const nb = cert.notBefore.value;
  const na = cert.notAfter.value;
  return at >= nb && at <= na;
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Extract the Subject Key Identifier (OID 2.5.29.14) as lowercase hex, if present. */
export function subjectKeyIdentifierHex(cert: Certificate): string | undefined {
  const ext = cert.extensions?.find((e) => e.extnID === '2.5.29.14');
  if (!ext) return undefined;
  try {
    // pkijs typing limitation: parsedValue for SubjectKeyIdentifier is the raw OctetString.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    const valueHex = (ext.parsedValue as any)?.valueBlock?.valueHex as ArrayBuffer | undefined;
    return valueHex ? bufferToHex(valueHex) : undefined;
  } catch {
    return undefined;
  }
}

/** Extract the Authority Key Identifier's keyIdentifier (OID 2.5.29.35) as lowercase hex, if present. */
export function authorityKeyIdentifierHex(cert: Certificate): string | undefined {
  const ext = cert.extensions?.find((e) => e.extnID === '2.5.29.35');
  if (!ext) return undefined;
  try {
    // pkijs typing limitation: parsedValue is an AuthorityKeyIdentifier instance.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    const keyIdentifier = (ext.parsedValue as any)?.keyIdentifier;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    const valueHex = keyIdentifier?.valueBlock?.valueHex as ArrayBuffer | undefined;
    return valueHex ? bufferToHex(valueHex) : undefined;
  } catch {
    return undefined;
  }
}

async function resolveByCryptographicVerification(
  child: Certificate,
  candidates: Certificate[],
): Promise<Certificate | undefined> {
  const verified: Certificate[] = [];
  for (const candidate of candidates) {
    try {
      if (await child.verify(candidate)) verified.push(candidate);
    } catch {
      /* signature didn't validate against this candidate — try the next one */
    }
  }
  if (verified.length <= 1) return verified[0];
  // 2026-08-23: más de un candidato verifica — renovación de CA que CONSERVÓ
  // el par de claves (mismo SKI, misma firma válida sobre el hijo). La firma
  // ya no discrimina; el único señal restante es la vigencia: preferir un
  // candidato vigente AHORA (embebido/aceptado, un cert caducado rompe la
  // cadena aunque su firma case) y, entre vigentes, el de notBefore más
  // reciente (la renovación más nueva). Sin vigentes, el de notBefore más
  // reciente igualmente — el menos malo, y determinista.
  const now = new Date();
  const live = verified.filter((c) => isWithinValidity(c, now));
  const pool = live.length > 0 ? live : verified;
  return pool.reduce((best, c) =>
    c.notBefore.value.getTime() > best.notBefore.value.getTime() ? c : best,
  );
}

/**
 * Resolve which of `candidates` is the REAL issuer of `child`, when more than
 * one candidate shares the subject DN of `child.issuer` (e.g. a renewed
 * intermediate CA that kept its predecessor's subject — real-world case: BCE
 * "AC BANCO CENTRAL DEL ECUADOR" 2011 vs 2019 subCAs share the exact same
 * subject DN but have different keys/serials).
 *
 * A plain `candidates.find((c) => c.subject.isEqual(child.issuer))` silently
 * picks whichever entry happens to be declared first — with no guarantee it's
 * the cert that actually signed `child`. That produced two symmetric bugs:
 * embedding the wrong intermediate when signing, and rejecting a real chain
 * when verifying (an expired 2011 subCA doesn't chain to a leaf issued by the
 * live 2019 subCA).
 *
 * Order of preference:
 *   1. Subject Key Identifier (candidate) == Authority Key Identifier
 *      (child) — the standard RFC 5280 signal, present on essentially every
 *      modern CA-issued cert, and unambiguous even across DN collisions.
 *   2. If AKI/SKI are unavailable (older certs sometimes omit them) or the
 *      match is still ambiguous, fall back to real cryptographic
 *      verification (`child.verify(candidate)`) over the DN-matching
 *      candidates — i.e. let pkijs' signature check pick the true issuer
 *      instead of guessing.
 *
 * Returns `undefined` when no candidate's subject matches `child.issuer` at
 * all, or when neither AKI/SKI nor cryptographic verification can
 * disambiguate (defensive — callers should treat this the same as "link not
 * found").
 */
export async function resolveIssuerCert(
  child: Certificate,
  candidates: Certificate[],
): Promise<Certificate | undefined> {
  const dnMatches = candidates.filter((c) => c.subject.isEqual(child.issuer));
  if (dnMatches.length === 0) return undefined;
  if (dnMatches.length === 1) return dnMatches[0];

  const childAki = authorityKeyIdentifierHex(child);
  if (childAki) {
    const byAki = dnMatches.filter((c) => subjectKeyIdentifierHex(c) === childAki);
    if (byAki.length === 1) return byAki[0];
    if (byAki.length > 1) return resolveByCryptographicVerification(child, byAki);
  }
  return resolveByCryptographicVerification(child, dnMatches);
}
