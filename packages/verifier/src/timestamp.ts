/**
 * verifyTimestamp — F6 Task 12.
 *
 * Verifies an embedded RFC 3161 TimeStampToken from the SignerInfo
 * unsignedAttributes (id-aa-signatureTimeStampToken,
 * 1.2.840.113549.1.9.16.2.14).
 *
 * Three-state result:
 *   - present:false, badge:'none'   → no token in CMS (legacy B-B).
 *   - present:true,  badge:'gold'   → all checks pass (imprint + chain + sig).
 *   - present:true,  badge:'silver' → token present but a check fails. The
 *     outer signature MUST NOT be downgraded by this — silver only adds a
 *     warning. Spec §6.2.
 *
 * The TSA's *inner* SignerInfo signature is computed over the inner
 * signedAttrs DER. parseTimestampToken in @firma-ec/tsa-client already
 * applies the [0] IMPLICIT (0xa0) → universal SET (0x31) patch from RFC
 * 5652 §5.4 (re-using `signedAttrs.toSchema(true).toBER(false)` — the same
 * trap we hit in F3 v0.4.4 when `encodedValue` returned 0 bytes on the
 * build path). We treat innerSignedAttrsDer as the canonical "signed-over"
 * form and re-import the TSA cert's SPKI to verify with WebCrypto.
 */

import { type HashAlgo, digest } from '@firma-ec/crypto-core';
import {
  ARCOTEL_PROXY_MAP,
  type ProxyMap,
  createAiaCertCache,
  extractCaIssuersUrls,
  fetchIssuerCertViaAia,
  isProxied,
} from '@firma-ec/ltv-validation';
import { type ParsedTimestampToken, parseTimestampToken } from '@firma-ec/tsa-client';
import {
  type AccreditedTsaAnchors,
  type TsaTrustRoot,
  validateTsaCertChain,
} from '@firma-ec/tsa-trust';
import { getIntermediates, getTrustRoots } from '@firma-ec/tsl-ec';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';

/**
 * F2 (2026-08-06) — AIA caIssuers fallback for the TSA chain check, same
 * mechanism and same trust boundary as F1 (packages/signer/chainIntermediates.ts):
 * only ever attempted when the local bundle (embedded token certs + the
 * @firma-ec/tsa-trust intermediates list) still can't complete the chain,
 * and `fetchIssuerCertViaAia` itself still enforces CA:TRUE + "actually
 * signed this cert" before returning anything — it can only help complete a
 * path to an ALREADY-trusted root, never grant new trust. Opt-in via this
 * param (undefined = old behavior, no network) so every existing unit test
 * of this module stays fully offline/deterministic by default.
 */
export interface TsaAiaFallbackOpts {
  /** Injectable for tests; defaults to `globalThis.fetch`. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout. Default 5000ms (same as ltv-validation's default). */
  timeoutMs?: number;
  proxyMap?: ProxyMap;
}

/**
 * Module-scoped, process-lifetime cache for AIA-resolved TSA issuer certs —
 * same rationale as `getTsaTrustRoots`/`getTsaTrustIntermediates`'s own
 * module-level caches. Without this, a multi-signature PDF where every
 * signature was stamped by the same not-yet-bundled TSA would re-fetch the
 * identical issuer cert once per signature (the exact "N sequential legs"
 * stall pattern already documented in index.ts's Android incident).
 */
const aiaCertCache = createAiaCertCache();

/** OID → WebCrypto hash name. */
const HASH_OID_TO_ALGO: Record<string, HashAlgo> = {
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};

/** EC namedCurve OID (in SPKI algorithmParams) → WebCrypto curve name. */
const EC_CURVE_OID_TO_NAME: Record<string, 'P-256' | 'P-384' | 'P-521'> = {
  '1.2.840.10045.3.1.7': 'P-256', // prime256v1 / secp256r1
  '1.3.132.0.34': 'P-384', // secp384r1
  '1.3.132.0.35': 'P-521', // secp521r1
};

export type TimestampBadge = 'gold' | 'silver' | 'none';

export type TimestampReason =
  | 'imprint_mismatch'
  | 'sig_invalid'
  | 'chain_invalid'
  | 'expired'
  | 'malformed'
  | 'no_tsa_cert';

export interface TimestampVerification {
  /** True iff a TimeStampToken was attached. */
  present: boolean;
  /** True iff every check passed (imprint + chain + signature). */
  valid: boolean;
  badge: TimestampBadge;
  /** TSTInfo.genTime when the token parsed. */
  signingTime?: Date;
  /** Subject CN of the TSA cert. */
  tsaIssuer?: string;
  /** Failure reason (silver state only). */
  reason?: TimestampReason;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toAb(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function cnFromRdn(rdn: {
  typesAndValues: { type: string; value: { valueBlock: { value?: string } } }[];
}): string | null {
  for (const tv of rdn.typesAndValues) {
    if (tv.type === '2.5.4.3') {
      const v = tv.value?.valueBlock?.value;
      if (typeof v === 'string') return v;
    }
  }
  return null;
}

function getCN(cert: Certificate): string | null {
  return cnFromRdn(
    cert.subject as unknown as {
      typesAndValues: { type: string; value: { valueBlock: { value?: string } } }[];
    },
  );
}

function getIssuerCN(cert: Certificate): string | null {
  return cnFromRdn(
    cert.issuer as unknown as {
      typesAndValues: { type: string; value: { valueBlock: { value?: string } } }[];
    },
  );
}

const OID_ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';

let accreditedCache: Promise<AccreditedTsaAnchors> | null = null;

/**
 * ARCOTEL-accredited ECIs also run the accredited timestamping services
 * (Security Data, BCE, UANATACA EC, …): their TSU certificates chain to the
 * same TSL roots the verifier pins for signatures. Offer those roots — only
 * real ones whose fingerprint matches the TSL, as in validatePath — and the
 * bundled subordinate CAs as extra TSA anchors, so a timestamp from any
 * accredited ECI is recognised without listing every TSA by hand.
 */
export function accreditedTsaAnchors(): Promise<AccreditedTsaAnchors> {
  accreditedCache ??= (async () => {
    const anchors: Certificate[] = [];
    for (const r of await getTrustRoots()) {
      if (r.isPlaceholder) continue;
      try {
        const der = pemToDerLocal(r.pemContent);
        const fp = Array.from(
          new Uint8Array(await crypto.subtle.digest('SHA-256', toAb(der))),
          (b) => b.toString(16).padStart(2, '0'),
        ).join('');
        if (fp !== r.fingerprintSha256) continue;
        anchors.push(new Certificate({ schema: fromBER(toAb(der)).result }));
      } catch {
        /* skip an unparseable root, as validatePath does */
      }
    }
    const intermediates: Certificate[] = [];
    for (const it of await getIntermediates()) {
      try {
        intermediates.push(
          new Certificate({ schema: fromBER(toAb(pemToDerLocal(it.pemContent))).result }),
        );
      } catch {
        /* skip unparseable */
      }
    }
    return { anchors, intermediates };
  })();
  return accreditedCache;
}

function pemToDerLocal(pem: string): Uint8Array {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s/g, '');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Verify the TSA's inner SignerInfo signature over its signedAttrs DER.
 *
 * Mirrors @firma-ec/verifier's `verifySignatureValue` for the outer signer,
 * but limited to RSA-PKCS1 + ECDSA-P256/P384 (the shapes used by the public
 * TSAs in our trust list — FreeTSA is RSA-2048-SHA-256).
 */
async function verifyInnerSignature(
  parsed: ParsedTimestampToken,
  tsaCert: Certificate,
): Promise<boolean> {
  const hash = HASH_OID_TO_ALGO[parsed.innerDigestAlgoOid];
  if (!hash) return false;

  // The TSA signs signedAttrs, not TSTInfo: TSTInfo is bound only through the
  // mandatory content-type and message-digest attributes (RFC 5652 §5.3/§11).
  // Without this check genTime and the imprint could be rewritten while the
  // signature below still verified (2026-09-23, reproduced on the FreeTSA KAT).
  if (parsed.innerContentTypeOid !== OID_ID_CT_TST_INFO) return false;
  if (!parsed.innerMessageDigest) return false;
  const tstDigest = new Uint8Array(await crypto.subtle.digest(hash, toAb(parsed.tstInfoDer)));
  if (!bytesEqual(tstDigest, parsed.innerMessageDigest)) return false;

  // Export pubkey from TSA cert.
  const spkiRaw = new Uint8Array(tsaCert.subjectPublicKeyInfo.toSchema().toBER(false));
  const spkiAb: ArrayBuffer = spkiRaw.buffer.slice(
    spkiRaw.byteOffset,
    spkiRaw.byteOffset + spkiRaw.byteLength,
  ) as ArrayBuffer;

  const sigOid = parsed.innerSigAlgoOid;
  const isRsaPkcs1 =
    sigOid === '1.2.840.113549.1.1.1' || // rsaEncryption (some TSAs)
    sigOid === '1.2.840.113549.1.1.11' ||
    sigOid === '1.2.840.113549.1.1.12' ||
    sigOid === '1.2.840.113549.1.1.13';
  const isEcdsa =
    sigOid === '1.2.840.10045.4.3.2' || // ecdsa-with-SHA256
    sigOid === '1.2.840.10045.4.3.3' || // ecdsa-with-SHA384
    sigOid === '1.2.840.10045.4.3.4' || // ecdsa-with-SHA512 (FreeTSA leaf is P-384/SHA-512)
    sigOid === '1.2.840.10045.2.1'; // ecPublicKey (some TSAs use the SPKI OID as sigAlg)

  try {
    if (isRsaPkcs1) {
      const pub = await crypto.subtle.importKey(
        'spki',
        spkiAb,
        { name: 'RSASSA-PKCS1-v1_5', hash },
        false,
        ['verify'],
      );
      return await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        pub,
        toAb(parsed.innerSignatureValue),
        toAb(parsed.innerSignedAttrsDer),
      );
    }
    if (isEcdsa) {
      // Derive namedCurve from SPKI's algorithmParams (an ObjectIdentifier
      // carrying the curve OID per RFC 5480 §2.1.1) — NOT from the hash algo.
      // FreeTSA's TSA leaf is ECDSA P-384 with SHA-512 (combo not matched by
      // a simple hash→curve map; e.g. SHA-512 with P-256 or P-384 is legal).
      const algParams = (
        tsaCert.subjectPublicKeyInfo as unknown as {
          algorithm: { algorithmParams?: { valueBlock?: { toString: () => string } } };
        }
      ).algorithm.algorithmParams;
      const curveOid = algParams?.valueBlock?.toString?.() ?? '';
      const namedCurve = EC_CURVE_OID_TO_NAME[curveOid];
      if (!namedCurve) return false;
      const pub = await crypto.subtle.importKey(
        'spki',
        spkiAb,
        { name: 'ECDSA', namedCurve },
        false,
        ['verify'],
      );
      // CMS encodes ECDSA as ASN.1 SEQ{r,s}; WebCrypto wants raw r||s. Field
      // size is determined by the curve, not the digest.
      const fieldBytes = namedCurve === 'P-256' ? 32 : namedCurve === 'P-384' ? 48 : 66;
      const raw = await asn1ToRawEcdsa(parsed.innerSignatureValue, fieldBytes);
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash },
        pub,
        toAb(raw),
        toAb(parsed.innerSignedAttrsDer),
      );
    }
    return false;
  } catch {
    return false;
  }
}

async function asn1ToRawEcdsa(asn1Sig: Uint8Array, fieldBytes: number): Promise<Uint8Array> {
  const parsed = fromBER(toAb(asn1Sig));
  if (parsed.offset === -1) throw new Error('ECDSA ASN.1 decode failed');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  const seq = (parsed.result as any).valueBlock.value as {
    valueBlock: { valueHex: ArrayBuffer };
  }[];
  const r = new Uint8Array(seq[0]!.valueBlock.valueHex);
  const s = new Uint8Array(seq[1]!.valueBlock.valueHex);
  function strip(b: Uint8Array): Uint8Array {
    let i = 0;
    while (i < b.length && b[i] === 0 && b.length - i > fieldBytes) i++;
    return b.subarray(i);
  }
  const out = new Uint8Array(fieldBytes * 2);
  const rs = strip(r);
  const ss = strip(s);
  out.set(rs, fieldBytes - rs.length);
  out.set(ss, fieldBytes * 2 - ss.length);
  return out;
}

/**
 * Verify an embedded RFC 3161 TimeStampToken.
 *
 * F7 T24 — generic imprint source.
 *
 * The function now accepts the imprint message in two forms:
 *
 *  (a) **Pre-hashed**: pass `{ imprintBytes }`. Used by document timestamps
 *      (B-LTA) where the imprint message is the byte-range coverage of the
 *      prior PDF revision — the caller has already extracted those bytes.
 *
 *  (b) **Hash-of-bytes**: pass either `{ imprintSource }` or a raw
 *      `Uint8Array` (legacy F6 positional form). Used by signature
 *      timestamps where the imprint is `SHA-{algo}(SignerInfo.signature)`.
 *
 * The hashAlgo is always taken from the parsed TSTInfo (not specified by
 * caller) — the TSA decided it when issuing the token.
 *
 * @param token  TimeStampToken bytes (CMS ContentInfo) — may be undefined.
 * @param imprint  Bytes to hash, OR pre-computed imprint, OR raw Uint8Array
 *                 for back-compat with F6 callers.
 * @param _trustRoots Optional override; defaults to in-package trust roots.
 */
export type VerifyTimestampImprint =
  | Uint8Array
  | { imprintSource: Uint8Array; imprintBytes?: undefined }
  | { imprintBytes: Uint8Array; imprintSource?: undefined };

export async function verifyTimestamp(
  token: Uint8Array | undefined,
  imprint: VerifyTimestampImprint,
  _trustRoots?: TsaTrustRoot[],
  aiaFallback?: TsaAiaFallbackOpts,
): Promise<TimestampVerification> {
  if (!token || token.length === 0) {
    return { present: false, valid: false, badge: 'none' };
  }

  let parsed: ParsedTimestampToken;
  try {
    parsed = parseTimestampToken(token);
  } catch {
    return { present: true, valid: false, badge: 'silver', reason: 'malformed' };
  }

  // Parse first TSA cert.
  if (parsed.tsaCertDers.length === 0) {
    return {
      present: true,
      valid: false,
      badge: 'silver',
      reason: 'no_tsa_cert',
      signingTime: parsed.signingTime,
    };
  }
  let tsaCert: Certificate;
  let tsaCertObj: { certificate: Certificate; der: Uint8Array; notBefore: Date; notAfter: Date };
  try {
    const der = parsed.tsaCertDers[0]!;
    const asn = fromBER(toAb(der));
    if (asn.offset === -1) throw new Error('asn1 decode');
    tsaCert = new Certificate({ schema: asn.result });
    tsaCertObj = {
      certificate: tsaCert,
      der,
      notBefore: tsaCert.notBefore.value as Date,
      notAfter: tsaCert.notAfter.value as Date,
    };
  } catch {
    return {
      present: true,
      valid: false,
      badge: 'silver',
      reason: 'malformed',
      signingTime: parsed.signingTime,
    };
  }

  const tsaIssuer = getCN(tsaCert) ?? undefined;
  const base = {
    present: true as const,
    signingTime: parsed.signingTime,
    ...(tsaIssuer ? { tsaIssuer } : {}),
  };

  // 1. Imprint check: hashAlgo from TSTInfo must match what we'd compute.
  //    F6 spec assumes SHA-256 imprint (signer-side default). Other algos
  //    are accepted as long as TSTInfo.hashAlgoOid maps to a supported one.
  const hash = HASH_OID_TO_ALGO[parsed.hashAlgoOid];
  if (!hash) {
    return { ...base, valid: false, badge: 'silver', reason: 'malformed' };
  }
  // Resolve the imprint shape into the actual bytes the parsed token claims
  // to seal. Three shapes accepted (see jsdoc above).
  let expectedImprint: Uint8Array;
  if (imprint instanceof Uint8Array) {
    expectedImprint = await digest(hash, imprint);
  } else if ('imprintBytes' in imprint && imprint.imprintBytes) {
    expectedImprint = imprint.imprintBytes;
  } else if ('imprintSource' in imprint && imprint.imprintSource) {
    expectedImprint = await digest(hash, imprint.imprintSource);
  } else {
    return { ...base, valid: false, badge: 'silver', reason: 'malformed' };
  }
  if (!bytesEqual(parsed.imprint, expectedImprint)) {
    return { ...base, valid: false, badge: 'silver', reason: 'imprint_mismatch' };
  }

  // 2. Inner signature verification (TSA signs TSTInfo).
  const sigValid = await verifyInnerSignature(parsed, tsaCert);
  if (!sigValid) {
    return { ...base, valid: false, badge: 'silver', reason: 'sig_invalid' };
  }

  // 3. Chain validation against TSA trust roots. Use TSTInfo.genTime as the
  //    'atTime' so we don't reject tokens whose TSA cert has since expired.
  const intermediates: Certificate[] = [];
  for (let i = 1; i < parsed.tsaCertDers.length; i++) {
    try {
      const der = parsed.tsaCertDers[i]!;
      const asn = fromBER(toAb(der));
      if (asn.offset === -1) continue;
      intermediates.push(new Certificate({ schema: asn.result }));
    } catch {
      // ignore unparseable intermediates
    }
  }
  const accredited = await accreditedTsaAnchors();
  let chain = await validateTsaCertChain(tsaCertObj, intermediates, parsed.signingTime, accredited);

  // F2 AIA self-heal — only when the local bundle (embedded + tsa-trust's
  // own intermediates) still didn't complete the chain, and the caller
  // opted in. Never attempted for tsa_eku_missing/expired/placeholder_only/
  // engine_error: an AIA fetch cannot fix any of those.
  if (!chain.ok && chain.reason === 'chain_invalid' && aiaFallback) {
    const proxyMap = aiaFallback.proxyMap ?? ARCOTEL_PROXY_MAP;
    const aiaCertLike = {
      der: tsaCertObj.der,
      subjectCN: getCN(tsaCert),
      issuerCN: getIssuerCN(tsaCert),
      notBefore: tsaCertObj.notBefore,
      notAfter: tsaCertObj.notAfter,
    };
    // Gate BEFORE attempting a fetch: an AIA URL absent from the allowlist
    // can never succeed in the browser anyway (CSP/CORS block it) — a
    // pass-through fetch there is pure downside (network beacon of which
    // document/TSA a user is verifying, or unbounded SSRF surface if this
    // ever ran server-side) with zero chance of resolving anything. Same
    // finding independently raised for this AND F1's sibling path (signer)
    // by both reviewers on 2026-08-06; scoped fix applied here first since
    // this is the newer, still-unmerged path.
    const aiaUrl = extractCaIssuersUrls(aiaCertLike)[0];
    const aiaAllowed = aiaUrl !== undefined && isProxied(aiaUrl, proxyMap);
    const aiaResult = aiaAllowed
      ? await fetchIssuerCertViaAia(aiaCertLike, {
          ...(aiaFallback.fetchImpl ? { fetchImpl: aiaFallback.fetchImpl } : {}),
          timeoutMs: aiaFallback.timeoutMs ?? 5000,
          proxyMap,
          cache: aiaCertCache,
        })
      : ({ ok: false, reason: 'no_aia' } as const);
    if (aiaResult.ok) {
      try {
        const asn = fromBER(toAb(aiaResult.certDer));
        if (asn.offset !== -1) {
          intermediates.push(new Certificate({ schema: asn.result }));
          chain = await validateTsaCertChain(
            tsaCertObj,
            intermediates,
            parsed.signingTime,
            accredited,
          );
        }
      } catch {
        // Malformed AIA response — keep the original chain_invalid result.
      }
    }
  }

  if (!chain.ok) {
    const reason: TimestampReason = chain.reason === 'expired' ? 'expired' : 'chain_invalid';
    return { ...base, valid: false, badge: 'silver', reason };
  }

  return { ...base, valid: true, badge: 'gold' };
}
