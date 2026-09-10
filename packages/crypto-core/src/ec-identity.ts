import { type Constructed, type ObjectIdentifier, type Sequence, fromBER } from 'asn1js';
import type { Certificate } from 'pkijs';
import { subjectInfo } from './x509';

/**
 * Identity extraction for Ecuadorian accredited certification authorities (ACE).
 *
 * The X.500 subject `serialNumber` RDN (OID 2.5.4.5) is NOT a dependable source
 * for the cédula, even though it is the field the standard reserves for it:
 *
 *   - ICERT-EC       → cédula present in 2.5.4.5.
 *   - ArgosData      → 2.5.4.5 absent entirely.
 *   - Security Data  → 2.5.4.5 holds an unrelated value (23- and 12-digit
 *                      strings observed across real certificates).
 *
 * Every ACE instead publishes identity under its own private OID arc, and all
 * of them reuse the same suffix scheme. Two placements are in use: ICERT-EC
 * nests the attributes inside subjectAltName as `otherName` entries, while
 * ArgosData and Security Data emit them as top-level certificate extensions.
 * Both are handled here.
 */

interface AceArc {
  readonly name: string;
  readonly arc: string;
}

/** Private arcs of the ACEs we have confirmed against real certificates. */
const ACE_ARCS: readonly AceArc[] = [
  { name: 'ICERT-EC', arc: '1.3.6.1.4.1.43745.1.3' },
  { name: 'ArgosData', arc: '1.3.6.1.4.1.59198.3' },
  { name: 'Security Data', arc: '1.3.6.1.4.1.37746.3' },
  { name: 'Banco Central del Ecuador', arc: '1.3.6.1.4.1.37947.3' },
  { name: 'Uanataca', arc: '1.3.6.1.4.1.47286.102.3' },
];

/** Suffixes shared by every ACE arc observed so far. */
const SUFFIX_CEDULA = '1';
const SUFFIX_GIVEN_NAME = '2';
const SUFFIX_SURNAME_1 = '3';
const SUFFIX_SURNAME_2 = '4';
/**
 * Role the holder signs under — only issued on legal-representative certs.
 *
 * Confirmed against REAL certificates of Security Data (in the repo's fixtures),
 * ArgosData and Uanataca (verified out of band: a legal-representative .p12
 * carries a person's cédula and a live company's RUC, so neither may enter this
 * repository). For the remaining arcs it is the shared scheme by convention,
 * with no sample to confirm it.
 */
const SUFFIX_JOB_TITLE = '5';
/** Company the holder represents. Absent on natural-person certificates. */
const SUFFIX_ORGANIZATION = '10';
/**
 * Tax ID. Whose it is depends on `.10`: on a legal-representative certificate
 * it is the COMPANY's, but on a natural-person one it is the holder's own
 * (their cédula plus an establishment code, so it starts with the cédula).
 * Every natural-person fixture in this repo — ArgosData, BCE, Uanataca —
 * publishes the holder's. Do not describe it as "the company's" on its own.
 */
const SUFFIX_RUC = '11';

const SUBJECT_ALT_NAME_OID = '2.5.29.17';
const SUBJECT_SERIAL_NUMBER_OID = '2.5.4.5';
/** organizationIdentifier — ArgosData carries the RUC here. */
const ORGANIZATION_IDENTIFIER_OID = '2.5.4.97';

/** Enterprise arc; identity attributes only ever appear beneath it. */
const PRIVATE_ENTERPRISE_ARC = '1.3.6.1.4.1.';

const OTHER_NAME_TYPE = 0;

/**
 * Prefixes that wrap the bare number in some issuances. The ETSI EN 319 412-1
 * §5.1.4 semantics identifiers are three letters of scheme plus a two-letter
 * country code; `CI-`/`RUC-` are ad-hoc forms seen in the wild.
 */
const ETSI_SEMANTICS_PREFIX_RE = /^[A-Z]{3}[A-Z]{2}-/;
const ADHOC_ID_PREFIXES = ['CI-', 'RUC-'] as const;

const CEDULA_DIGITS = 10;
const RUC_DIGITS = 13;
/** Province codes run 01–24, plus 30 for consular registrations. */
const MIN_PROVINCE = 1;
const MAX_PROVINCE = 24;
const CONSULAR_PROVINCE = 30;
/** A third digit above this marks a company RUC, not a natural person. */
const MAX_NATURAL_PERSON_THIRD_DIGIT = 5;

export interface EcCertIdentity {
  /** National ID of the natural person holding the certificate. */
  cedula?: string | undefined;
  /** Tax ID (13 digits) when the certificate carries one. */
  ruc?: string | undefined;
  /** Given names, when published separately from the CN. */
  givenName?: string | undefined;
  /** Surnames, joined when the ACE splits them into two attributes. */
  surname?: string | undefined;
  /**
   * Legal name of the company the holder represents, as published by the ACE.
   * Present only on legal-representative / corporate-membership certificates.
   */
  organization?: string | undefined;
  /** Role the holder signs under, e.g. REPRESENTANTE LEGAL, GERENTE GENERAL. */
  jobTitle?: string | undefined;
  /** Which ACE arc matched, for diagnostics. `undefined` when none did. */
  ace?: string | undefined;
  /** Where the cédula was found. Useful to explain an empty result. */
  cedulaSource?: 'ace-arc' | 'subject-dn' | 'heuristic' | undefined;
}

/**
 * Validate an Ecuadorian cédula: province range, natural-person marker and the
 * mod-10 check digit. Used to qualify heuristic matches, never to reject a
 * value published by a known ACE arc — a legitimate holder may be a foreign
 * national whose identifier does not follow the national scheme.
 */
export function isValidEcCedula(value: string): boolean {
  if (!new RegExp(`^\\d{${CEDULA_DIGITS}}$`).test(value)) return false;

  const province = Number(value.slice(0, 2));
  if (province < MIN_PROVINCE || (province > MAX_PROVINCE && province !== CONSULAR_PROVINCE)) {
    return false;
  }
  if (Number(value[2]) > MAX_NATURAL_PERSON_THIRD_DIGIT) return false;

  let sum = 0;
  for (let i = 0; i < CEDULA_DIGITS - 1; i++) {
    // Coefficients alternate 2,1,2,1… starting at the first digit.
    let digit = Number(value[i]) * (i % 2 === 0 ? 2 : 1);
    if (digit > 9) digit -= 9;
    sum += digit;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  return checkDigit === Number(value[CEDULA_DIGITS - 1]);
}

/** Strip an ETSI semantics or ad-hoc prefix, leaving the bare identifier. */
export function stripIdPrefix(value: string): string {
  const trimmed = value.trim();
  for (const prefix of ADHOC_ID_PREFIXES) {
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  if (ETSI_SEMANTICS_PREFIX_RE.test(trimmed)) {
    return trimmed.slice(trimmed.indexOf('-') + 1);
  }
  return trimmed;
}

/** Decode a DER-encoded character string; `null` when it is not one. */
function derToString(bytes: Uint8Array): string | null {
  try {
    const parsed = fromBER(bytes);
    if (parsed.offset === -1) return null;
    const value = (parsed.result as { valueBlock?: { value?: unknown } }).valueBlock?.value;
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
}

/** Read the `otherName` pairs carried inside subjectAltName. */
function collectOtherNames(cert: Certificate, into: Map<string, string>): void {
  const san = cert.extensions?.find((e) => e.extnID === SUBJECT_ALT_NAME_OID);
  const altNames = (
    san?.parsedValue as { altNames?: { type: number; value: unknown }[] } | undefined
  )?.altNames;
  if (!altNames) return;

  for (const generalName of altNames) {
    if (generalName.type !== OTHER_NAME_TYPE) continue;
    try {
      // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
      const seq = generalName.value as Sequence;
      const oid = (seq.valueBlock.value[0] as ObjectIdentifier).valueBlock.toString();
      const wrapper = seq.valueBlock.value[1] as Constructed;
      const inner = wrapper.valueBlock.value[0] as { valueBlock?: { value?: unknown } };
      const text = inner.valueBlock?.value;
      if (typeof text === 'string' && text !== '') into.set(oid, text);
    } catch {
      // A malformed otherName is not a reason to lose the rest of the identity.
      continue;
    }
  }
}

/** Every OID→string pair the certificate publishes, from both placements. */
function collectOidValues(cert: Certificate): Map<string, string> {
  const values = new Map<string, string>();

  for (const ext of cert.extensions ?? []) {
    if (ext.extnID === SUBJECT_ALT_NAME_OID) continue;
    const text = derToString(ext.extnValue.valueBlock.valueHexView);
    if (text !== null && text !== '') values.set(ext.extnID, text);
  }
  collectOtherNames(cert, values);

  return values;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed === '' ? undefined : trimmed;
}

/**
 * Extract the holder's identity, trying each source in descending order of
 * reliability: the ACE's own arc, then the subject DN, then a checksum-guarded
 * scan of any remaining private attribute.
 */
export function ecCertIdentity(cert: Certificate): EcCertIdentity {
  const values = collectOidValues(cert);
  const identity: EcCertIdentity = {};

  // 1. A known ACE arc is authoritative — take its value as published.
  for (const { name, arc } of ACE_ARCS) {
    const cedula = nonEmpty(values.get(`${arc}.${SUFFIX_CEDULA}`));
    if (cedula === undefined) continue;

    identity.cedula = stripIdPrefix(cedula);
    identity.cedulaSource = 'ace-arc';
    identity.ace = name;

    identity.ruc = nonEmpty(values.get(`${arc}.${SUFFIX_RUC}`));
    identity.givenName = nonEmpty(values.get(`${arc}.${SUFFIX_GIVEN_NAME}`));
    identity.organization = nonEmpty(values.get(`${arc}.${SUFFIX_ORGANIZATION}`));
    identity.jobTitle = nonEmpty(values.get(`${arc}.${SUFFIX_JOB_TITLE}`));

    const surnames = [
      nonEmpty(values.get(`${arc}.${SUFFIX_SURNAME_1}`)),
      nonEmpty(values.get(`${arc}.${SUFFIX_SURNAME_2}`)),
    ].filter((s): s is string => s !== undefined);
    identity.surname = surnames.length > 0 ? surnames.join(' ') : undefined;
    break;
  }

  const subject = subjectInfo(cert);

  // 2. The subject DN, only when it actually holds an Ecuadorian identifier.
  if (identity.cedula === undefined) {
    const dnValue = nonEmpty(subject.raw['serialNumber']);
    if (dnValue !== undefined) {
      const bare = stripIdPrefix(dnValue);
      const isRuc = new RegExp(`^\\d{${RUC_DIGITS}}$`).test(bare);

      // A natural person's RUC is their cédula plus an establishment code, so
      // its prefix is the cédula. A company's RUC is not, and truncating it
      // would invent an identifier that belongs to nobody — publish only the
      // RUC in that case.
      const candidate = isRuc ? bare.slice(0, CEDULA_DIGITS) : bare;
      if (isValidEcCedula(candidate)) {
        identity.cedula = candidate;
        identity.cedulaSource = 'subject-dn';
      }
      if (isRuc) identity.ruc = bare;
    }
  }

  // 3. Last resort for ACEs whose arc we have not mapped yet. The checksum is
  //    what makes this safe: an arbitrary private attribute will not pass it.
  if (identity.cedula === undefined) {
    for (const [oid, value] of values) {
      if (!oid.startsWith(PRIVATE_ENTERPRISE_ARC)) continue;
      const bare = stripIdPrefix(value);
      if (isValidEcCedula(bare)) {
        identity.cedula = bare;
        identity.cedulaSource = 'heuristic';
        break;
      }
    }
  }

  // organizationIdentifier is the remaining place a RUC hides.
  if (identity.ruc === undefined) {
    const orgId = cert.subject.typesAndValues.find((tv) => tv.type === ORGANIZATION_IDENTIFIER_OID);
    const bare = orgId ? stripIdPrefix(String(orgId.value.valueBlock.value)) : undefined;
    if (bare !== undefined && new RegExp(`^\\d{${RUC_DIGITS}}$`).test(bare)) identity.ruc = bare;
  }

  // No DN fallback for `organization`: the subject `O` RDN does not mean the
  // same thing across ACEs. ArgosData puts the represented company there, but
  // Security Data and the BCE put their OWN name ("SECURITY DATA S.A. 2"), so
  // falling back would attribute the issuer's identity to the holder.

  // The DN still wins for names when the ACE arc published none.
  identity.givenName ??= nonEmpty(subject.raw['GN']);
  identity.surname ??= nonEmpty(subject.raw['SN']);

  return identity;
}

/** Exposed for tests that need to reach the private helpers. */
export const __internals = {
  ACE_ARCS,
  SUBJECT_SERIAL_NUMBER_OID,
  collectOidValues,
};
