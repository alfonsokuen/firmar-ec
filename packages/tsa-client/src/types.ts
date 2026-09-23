/**
 * Public type surface for @firma-ec/tsa-client.
 * Mirrors spec docs/superpowers/specs/2026-05-09-firma-ec-F6-TSA-design.md §3.1.
 */

export type HashAlgo = 'SHA-256' | 'SHA-384';

/** Minimal parsed-cert shape used by the TSA client (subset of verifier ParsedCert). */
export interface ParsedCert {
  /** Subject Common Name (or null if absent). */
  subjectCN: string | null;
  /** Issuer Common Name (or null if absent). */
  issuerCN: string | null;
  /** DER bytes of the cert. */
  der: Uint8Array;
  /** notBefore / notAfter from validity. */
  notBefore: Date;
  notAfter: Date;
}

export interface TimestampOk {
  /** RFC 3161 TimeStampToken (ContentInfo DER). */
  token: Uint8Array;
  /** TSA URL actually used. */
  tsaUrl: string;
  /** Hash algorithm used for messageImprint. */
  hashAlgo: HashAlgo;
  /** Time reported by the TSA (TSTInfo.genTime). */
  signingTime: Date;
  /** TSA signing certificate (parsed). */
  tsaCert: ParsedCert;
  /** Serial number of the TSTInfo (per RFC 3161). */
  serialNumberHex: string;
}

export type TimestampError =
  | { error: 'timeout'; detail?: string }
  | { error: 'rate_limited'; detail?: string }
  | { error: 'malformed'; detail?: string }
  | { error: 'rejected'; detail: string }
  | { error: 'network'; detail?: string };

export type TimestampResult = TimestampOk | TimestampError;

export interface RequestTimestampOpts {
  /** TSA URL. Default https://freetsa.org/tsr */
  url?: string;
  /** Request timeout in ms. Default 8000. */
  timeoutMs?: number;
  /** Hash algorithm for messageImprint. Default 'SHA-256'. */
  hashAlgo?: HashAlgo;
  /** AbortSignal for cancellation (overrides timeoutMs). */
  signal?: AbortSignal;
}

export interface ParsedTimestampToken {
  /** TSTInfo.messageImprint.hashedMessage */
  imprint: Uint8Array;
  /** TSTInfo.messageImprint.hashAlgorithm OID. */
  hashAlgoOid: string;
  /** TSTInfo.genTime. */
  signingTime: Date;
  /** TSTInfo.serialNumber as hex. */
  serialNumberHex: string;
  /** TSTInfo.nonce raw bytes (when present). */
  nonce?: Uint8Array;
  /** TSA certificates from SignedData.certificates (DER). */
  tsaCertDers: Uint8Array[];
  /** Inner SignerInfo of the TimeStampToken — for chain + signature verification. */
  innerSignedAttrsDer: Uint8Array;
  innerSignatureValue: Uint8Array;
  innerSigAlgoOid: string;
  innerDigestAlgoOid: string;
  /** DER of the TSTInfo (the eContent the TSA's message-digest attribute covers). */
  tstInfoDer: Uint8Array;
  /** Value of the signed `message-digest` attribute (RFC 5652 §11.2), when present. */
  innerMessageDigest?: Uint8Array;
  /** Value of the signed `content-type` attribute (RFC 5652 §11.1), when present. */
  innerContentTypeOid?: string;
}
