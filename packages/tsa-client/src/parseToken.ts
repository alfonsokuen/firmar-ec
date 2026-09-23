/**
 * parseTimestampToken — standalone parser for an RFC 3161 TimeStampToken.
 *
 * A TimeStampToken is a CMS ContentInfo wrapping SignedData whose
 * encapContentInfo.eContent is a DER-encoded TSTInfo.
 *
 * Exported for reuse by @firma-ec/verifier (verifyTimestamp wires this up).
 *
 * The TSTInfo schema (RFC 3161 §2.4.2):
 *   TSTInfo ::= SEQUENCE  {
 *     version                INTEGER  { v1(1) },
 *     policy                 TSAPolicyId,
 *     messageImprint         MessageImprint,
 *     serialNumber           INTEGER,
 *     genTime                GeneralizedTime,
 *     accuracy               Accuracy                  OPTIONAL,
 *     ordering               BOOLEAN                   DEFAULT FALSE,
 *     nonce                  INTEGER                   OPTIONAL,
 *     tsa                    [0] GeneralName           OPTIONAL,
 *     extensions             [1] IMPLICIT Extensions   OPTIONAL
 *   }
 */

import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { ParsedTimestampToken } from './types';

// CMS OIDs
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

function getInnerArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function asn1ToBytes(node: { toBER: (sized: boolean) => ArrayBuffer }): Uint8Array {
  return new Uint8Array(node.toBER(false));
}

function intToHex(int: asn1js.Integer): string {
  // valueBlock.valueHex is an ArrayBuffer of the magnitude bytes.
  const ab =
    (int.valueBlock as unknown as { valueHexView?: Uint8Array; valueHex?: ArrayBuffer })
      .valueHexView ??
    new Uint8Array((int.valueBlock as unknown as { valueHex: ArrayBuffer }).valueHex);
  let out = '';
  for (let i = 0; i < ab.length; i++) {
    const v = ab[i] as number;
    out += v.toString(16).padStart(2, '0');
  }
  return out;
}

function bytesFromOctetString(os: asn1js.OctetString): Uint8Array {
  const view = (os.valueBlock as unknown as { valueHexView?: Uint8Array; valueHex?: ArrayBuffer })
    .valueHexView;
  if (view) return new Uint8Array(view);
  const ab = (os.valueBlock as unknown as { valueHex: ArrayBuffer }).valueHex;
  return new Uint8Array(ab);
}

function bytesFromInteger(int: asn1js.Integer): Uint8Array {
  const view = (int.valueBlock as unknown as { valueHexView?: Uint8Array; valueHex?: ArrayBuffer })
    .valueHexView;
  if (view) return new Uint8Array(view);
  const ab = (int.valueBlock as unknown as { valueHex: ArrayBuffer }).valueHex;
  return new Uint8Array(ab);
}

/**
 * Parse a TimeStampToken's outer ContentInfo + inner SignedData + TSTInfo.
 * Returns extracted fields + raw signedAttrs/signature bytes for downstream
 * cryptographic verification by the caller (verifier package).
 */
export function parseTimestampToken(token: Uint8Array): ParsedTimestampToken {
  const ab = getInnerArrayBuffer(token);
  const outer = asn1js.fromBER(ab);
  if (outer.offset === -1) throw new Error('token: outer ASN.1 decode failed');

  const ci = new pkijs.ContentInfo({ schema: outer.result });
  if (ci.contentType !== OID_SIGNED_DATA) {
    throw new Error(`token: expected SignedData, got OID ${ci.contentType}`);
  }

  const sd = new pkijs.SignedData({ schema: ci.content });

  // Verify eContentType is id-ct-TSTInfo.
  const eciTypeOid = sd.encapContentInfo.eContentType;
  if (eciTypeOid !== OID_ID_CT_TST_INFO) {
    throw new Error(
      `token: encapContentInfo.eContentType expected ${OID_ID_CT_TST_INFO}, got ${eciTypeOid}`,
    );
  }

  const eContent = sd.encapContentInfo.eContent;
  if (!eContent) throw new Error('token: encapContentInfo.eContent missing');

  // eContent is an OCTET STRING whose value is the DER encoding of TSTInfo.
  const tstInfoBytes = bytesFromOctetString(eContent);

  // Parse TSTInfo manually.
  const tstAb = getInnerArrayBuffer(tstInfoBytes);
  const tstOuter = asn1js.fromBER(tstAb);
  if (tstOuter.offset === -1) throw new Error('token: TSTInfo ASN.1 decode failed');
  if (!(tstOuter.result instanceof asn1js.Sequence))
    throw new Error('token: TSTInfo not a SEQUENCE');

  const tstSeq = tstOuter.result.valueBlock.value;
  if (tstSeq.length < 5) throw new Error('token: TSTInfo too short');

  // [0] version INTEGER
  if (!(tstSeq[0] instanceof asn1js.Integer)) throw new Error('token: TSTInfo.version missing');

  // [1] policy OID
  // [2] MessageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const messageImprintNode = tstSeq[2];
  if (!(messageImprintNode instanceof asn1js.Sequence))
    throw new Error('token: messageImprint not SEQUENCE');
  const miInner = messageImprintNode.valueBlock.value;
  const algIdSeq = miInner[0];
  const hashedNode = miInner[1];
  if (!(algIdSeq instanceof asn1js.Sequence))
    throw new Error('token: messageImprint.hashAlgorithm not SEQUENCE');
  if (!(hashedNode instanceof asn1js.OctetString))
    throw new Error('token: messageImprint.hashedMessage not OCTET STRING');
  const algIdOidNode = algIdSeq.valueBlock.value[0];
  const hashAlgoOid =
    (
      algIdOidNode as unknown as { valueBlock: { toString: () => string } }
    )?.valueBlock?.toString?.() ?? '';
  const imprint = bytesFromOctetString(hashedNode);

  // [3] serialNumber INTEGER
  const serialNode = tstSeq[3];
  if (!(serialNode instanceof asn1js.Integer)) throw new Error('token: serialNumber not INTEGER');
  const serialNumberHex = intToHex(serialNode);

  // [4] genTime GeneralizedTime
  const genTimeNode = tstSeq[4];
  if (!(genTimeNode instanceof asn1js.GeneralizedTime)) {
    throw new Error('token: genTime not GeneralizedTime');
  }
  const signingTime = genTimeNode.toDate();

  // Optional fields after index 4: accuracy, ordering, nonce, [0] tsa, [1] extensions.
  // Walk and pick out nonce (first INTEGER after index 4 that isn't 'ordering' BOOLEAN).
  let nonce: Uint8Array | undefined;
  for (let i = 5; i < tstSeq.length; i++) {
    const node = tstSeq[i];
    if (node instanceof asn1js.Integer) {
      nonce = bytesFromInteger(node);
      break;
    }
  }

  // SignedData.certificates → DER list
  const tsaCertDers: Uint8Array[] = [];
  const certs = (sd as unknown as { certificates?: pkijs.Certificate[] | undefined }).certificates;
  if (Array.isArray(certs)) {
    for (const c of certs) {
      // Filter out CertificateChoices that aren't Certificates (e.g. AttributeCertificate).
      if (c instanceof pkijs.Certificate) {
        tsaCertDers.push(asn1ToBytes(c.toSchema()));
      }
    }
  }

  // Inner SignerInfo (assume exactly 1 — RFC 3161 §2.4.2 says "ONE SignerInfo")
  const signerInfos = (sd as unknown as { signerInfos: pkijs.SignerInfo[] }).signerInfos;
  if (!Array.isArray(signerInfos) || signerInfos.length === 0) {
    throw new Error('token: no SignerInfo');
  }
  const si = signerInfos[0]!;

  // signedAttrs are stored on SignerInfo.signedAttrs; encode them as a SET-tagged DER for
  // the verifier to recompute the digest. Apply the [0] → SET (0xa0 → 0x31) patch to
  // produce the "digestable" form per RFC 5652 §5.4.
  let innerSignedAttrsDer = new Uint8Array(0);
  const signedAttrs = (
    si as unknown as {
      signedAttrs?:
        | { toSchema: (encode: boolean) => { toBER: (sized: boolean) => ArrayBuffer } }
        | undefined;
    }
  ).signedAttrs;
  if (signedAttrs) {
    // Pass `encode=true` to round-trip cleanly when this token was built in-memory.
    const der = new Uint8Array(signedAttrs.toSchema(true).toBER(false));
    if (der.length > 0 && der[0] === 0xa0) der[0] = 0x31;
    innerSignedAttrsDer = der;
  }

  // signatureValue OCTET STRING
  // The signed attributes bind the signature to the TSTInfo only through
  // message-digest = hash(eContent). Expose it so the verifier can check it;
  // without that check TSTInfo (genTime, imprint) can be rewritten while the
  // TSA's signature over signedAttrs still verifies.
  let innerMessageDigest: Uint8Array | undefined;
  let innerContentTypeOid: string | undefined;
  const attrs = (
    si as unknown as {
      signedAttrs?: { attributes?: { type: string; values: asn1js.AsnType[] }[] };
    }
  ).signedAttrs?.attributes;
  for (const a of attrs ?? []) {
    const v = a.values[0];
    if (a.type === OID_MESSAGE_DIGEST && v instanceof asn1js.OctetString) {
      innerMessageDigest = bytesFromOctetString(v);
    } else if (a.type === OID_CONTENT_TYPE && v instanceof asn1js.ObjectIdentifier) {
      innerContentTypeOid = v.valueBlock.toString();
    }
  }

  const sigOs = (si as unknown as { signature: asn1js.OctetString }).signature;
  const innerSignatureValue = bytesFromOctetString(sigOs);

  const innerSigAlgoOid = (si as unknown as { signatureAlgorithm: { algorithmId: string } })
    .signatureAlgorithm.algorithmId;
  const innerDigestAlgoOid = (si as unknown as { digestAlgorithm: { algorithmId: string } })
    .digestAlgorithm.algorithmId;

  return {
    imprint,
    hashAlgoOid,
    signingTime,
    serialNumberHex,
    ...(nonce !== undefined ? { nonce } : {}),
    tsaCertDers,
    innerSignedAttrsDer,
    innerSignatureValue,
    innerSigAlgoOid,
    innerDigestAlgoOid,
    tstInfoDer: tstInfoBytes,
    ...(innerMessageDigest !== undefined ? { innerMessageDigest } : {}),
    ...(innerContentTypeOid !== undefined ? { innerContentTypeOid } : {}),
  };
}
