import { digest, isWithinValidity, toHex } from '@firma-ec/crypto-core';
import type { TrustRoot } from '@firma-ec/tsl-ec';
import { fromBER } from 'asn1js';
import { Certificate, CertificateChainValidationEngine } from 'pkijs';
import { ERR_CHAIN_FAIL, VerificationError } from './errors';

export interface PathResult {
  success: boolean;
  matchedRoot?: TrustRoot | undefined;
  chain: Certificate[];
  error?: string | undefined;
  /** Specific check warnings (e.g., key usage borderline, placeholder roots skipped) */
  warnings: string[];
  /**
   * True when the leaf→issuer walk could NOT reach a self-signed certificate
   * at all — i.e. some certificate in the middle of the chain has no known
   * issuer in the supplied cert pool (signer cert + intermediates + trusted
   * roots).
   *
   * SECURITY NOTE (2026-08-05 CRITICAL fix): the pool the walk climbs
   * includes `intermediates`, which are the certificates the SIGNER chose to
   * embed in the CMS — attacker-controlled input. An attacker can mint their
   * own rogue CA, sign a leaf with it, and simply NOT embed the rogue CA in
   * the PDF. The walk then gets stuck for exactly the same reason a
   * legitimate-but-not-yet-bundled intermediate would: no issuer found in the
   * pool. `chainIncomplete` therefore CANNOT be used to distinguish "this is
   * probably a real ACE we haven't bundled yet" from "this is a forged
   * chain" — the signer controls the signal. It exists ONLY to pick a more
   * honest user-facing MESSAGE (mentions "an intermediate CA may be
   * missing" instead of a blunt fraud-sounding message). It must NEVER be
   * used to weaken the verdict `status` below `invalid`/rejected — consumers
   * keep rejecting exactly as they do for a known-but-unaccredited root.
   * Always `false` when `success` is `true`.
   */
  chainIncomplete: boolean;
  /**
   * True when the chain is otherwise valid but the signer cert's keyUsage
   * asserts neither digitalSignature nor nonRepudiation (not a signing cert).
   * Always accompanied by `success: false`.
   */
  keyUsageNotSigning?: boolean;
}

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';

function extensionOf(cert: Certificate, oid: string) {
  return cert.extensions?.find((e) => e.extnID === oid);
}

/** basicConstraints cA=true and, when keyUsage is present, keyCertSign. */
function isIssuingCa(cert: Certificate): boolean {
  const bc = extensionOf(cert, OID_BASIC_CONSTRAINTS)?.parsedValue as { cA?: boolean } | undefined;
  if (bc?.cA !== true) return false;
  const ku = extensionOf(cert, OID_KEY_USAGE);
  if (!ku) return true;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  const bits = new Uint8Array((ku.parsedValue as any).valueBlock.valueHex as ArrayBuffer);
  return ((bits[0] ?? 0) & 0x04) !== 0; // bit 5 = keyCertSign
}

/**
 * A TSL root without basicConstraints (X.509 v1, e.g. "APPFIRMAS S.A. Root
 * AC" 2025) is rejected by pkijs as a path anchor: it demands cA=true on every
 * cert of the path, the anchor included, so every chain under such a root
 * failed. For those roots only, a subordinate CA from the pool becomes the
 * pkijs anchor — attributed to the root — when the root is valid at `atTime`
 * and the subordinate is an issuing CA whose signature verifies with the
 * pinned root's key. That signature check is what keeps a forged subordinate
 * carrying the root's DN out; pkijs then validates the rest of the path.
 */
async function addDelegatedAnchors(
  trustedCerts: Certificate[],
  usableRoots: TrustRoot[],
  pool: Certificate[],
  atTime: Date,
): Promise<void> {
  const rootCount = trustedCerts.length;
  for (let i = 0; i < rootCount; i++) {
    const root = trustedCerts[i]!;
    if (extensionOf(root, OID_BASIC_CONSTRAINTS)) continue;
    if (!isWithinValidity(root, atTime)) continue;
    for (const candidate of pool) {
      if (!candidate.issuer.isEqual(root.subject) || candidate.subject.isEqual(root.subject))
        continue;
      if (!isIssuingCa(candidate)) continue;
      if (trustedCerts.some((t) => sameTbs(t, candidate))) continue;
      let signedByRoot = false;
      try {
        signedByRoot = await candidate.verify(root);
      } catch {
        signedByRoot = false;
      }
      if (!signedByRoot) continue;
      trustedCerts.push(candidate);
      usableRoots.push(usableRoots[i]!);
    }
  }
}

/**
 * Same certificate content: byte-equal TBSCertificate, the identity pkijs's
 * own chain-engine dedup uses.
 */
function sameTbs(a: Certificate, b: Certificate): boolean {
  const x = a.tbsView;
  const y = b.tbsView;
  // An empty view means "not decoded from DER": never a proof of identity.
  if (x.byteLength === 0 || x.byteLength !== y.byteLength) return false;
  for (let i = 0; i < x.byteLength; i++) if (x[i] !== y[i]) return false;
  return true;
}

/**
 * Walk from `leaf` upward through `pool` (candidate issuer certs) following
 * issuer DNs — no signature checks, so it only ever picks the user-facing
 * `chainIncomplete` MESSAGE and never a trust decision. Follows
 * issuer links until a self-signed certificate is reached, or the walk gets
 * stuck because no cert in `pool` matches the current issuer. Returns the
 * terminal self-signed certificate when reached, or `undefined` when the
 * chain could not be completed — i.e. a subordinate CA cert is missing from
 * `pool` (bundled intermediates + roots), NOT that the terminal CA is known
 * but untrusted.
 */
function walkToSelfSigned(leaf: Certificate, pool: Certificate[]): Certificate | undefined {
  let cur: Certificate | undefined = leaf;
  for (let i = 0; i < 12 && cur !== undefined; i++) {
    if (cur.subject.isEqual(cur.issuer)) return cur;
    const issuer: Certificate | undefined = pool.find((c) => c.subject.isEqual(cur!.issuer));
    if (!issuer || issuer === cur) return undefined;
    cur = issuer;
  }
  return undefined;
}

function pemToCert(pem: string): Certificate {
  const b64 = pem.replace(/-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\s/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const asn = fromBER(
    der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer,
  );
  if (asn.offset === -1) throw new Error('PEM ASN.1 decode failed');
  return new Certificate({ schema: asn.result });
}

export async function validatePath(
  signerCert: Certificate,
  intermediates: Certificate[],
  roots: TrustRoot[],
  atTime: Date,
): Promise<PathResult> {
  const warnings: string[] = [];

  // Convert TrustRoot PEMs to pkijs Certificates; skip placeholders and fingerprint mismatches
  const trustedCerts: Certificate[] = [];
  const usableRoots: TrustRoot[] = [];

  for (const r of roots) {
    if (r.isPlaceholder) continue;

    try {
      const cert = pemToCert(r.pemContent);
      // Verify fingerprint matches what TSL claims — guard against silent cert substitution
      const der = new Uint8Array(cert.toSchema().toBER(false));
      const fp = toHex(await digest('SHA-256', der));
      if (fp !== r.fingerprintSha256) {
        warnings.push(
          `TSL fingerprint mismatch for ${r.slug}: tsl=${r.fingerprintSha256.slice(0, 16)} actual=${fp.slice(0, 16)}`,
        );
        continue; // refuse to trust a root whose fingerprint changed silently
      }
      trustedCerts.push(cert);
      usableRoots.push(r);
    } catch (e) {
      warnings.push(`Failed to parse trust root ${r.slug}: ${(e as Error).message}`);
    }
  }

  await addDelegatedAnchors(trustedCerts, usableRoots, intermediates, atTime);

  if (trustedCerts.length === 0) {
    const allPlaceholders = roots.length > 0 && roots.every((r) => r.isPlaceholder);
    const error = allPlaceholders
      ? 'All trust roots are placeholders; replace PEMs before enabling chain validation'
      : 'No usable trust roots after fingerprint check';
    return {
      success: false,
      chain: [],
      warnings,
      chainIncomplete: false,
      ...(error ? { error } : {}),
    };
  }

  // pkijs 3.x builds the path from the LAST element of `certs`, after a dedup
  // that keeps the FIRST copy of any duplicate (`leafCert =
  // localCerts[localCerts.length - 1]` in CertificateChainValidationEngine).
  // So the signer must go last and every other copy of it must be dropped
  // first — with `[signerCert, ...intermediates]` pkijs validated whichever
  // cert ended the pool, never the signer (2026-09-23: a leaf self-issued
  // under a real subCA's DN verified `valid`, and genuine multi-signature
  // signers got `untrusted_root` when a sibling's leaf ended the pool).
  const pool = intermediates.filter((c) => !sameTbs(c, signerCert));
  const engine = new CertificateChainValidationEngine({
    certs: [...pool, signerCert],
    trustedCerts,
    checkDate: atTime,
  });

  let result;
  try {
    result = await engine.verify();
  } catch (e) {
    const msg = `Chain engine threw: ${(e as Error).message}`;
    return { success: false, chain: [], error: msg, warnings, chainIncomplete: false };
  }

  if (!result.result) {
    const error = result.resultMessage ?? 'pkijs chain validation failed';
    // `chainIncomplete` only selects which MESSAGE to show (see the doc on
    // the field above) — it must never soften `status` in the caller, since
    // `intermediates` is attacker-controlled (embedded by the signer).
    const reachedSelfSigned =
      walkToSelfSigned(signerCert, [...trustedCerts, ...pool]) !== undefined;
    return { success: false, chain: [], error, warnings, chainIncomplete: !reachedSelfSigned };
  }

  // Fail closed unless pkijs verified the path of THIS signer. This is the
  // invariant the ordering above establishes; checking it guards against any
  // future change in pkijs's leaf selection or dedup.
  const chain: Certificate[] = result.certificatePath ?? [];
  const pathLeaf = chain[0];
  if (!pathLeaf || !sameTbs(pathLeaf, signerCert)) {
    return {
      success: false,
      chain: [],
      error: 'Chain engine validated a certificate other than the signer',
      warnings,
      chainIncomplete: false,
    };
  }

  // The matched root is the anchor pkijs cryptographically verified (the last
  // cert of the verified path), not the result of a DN-only walk.
  const anchor = chain[chain.length - 1];
  const anchorIdx = anchor ? trustedCerts.findIndex((t) => sameTbs(t, anchor)) : -1;
  const matchedRoot = anchorIdx >= 0 ? usableRoots[anchorIdx] : undefined;
  if (!matchedRoot) {
    return {
      success: false,
      chain,
      error: 'Chain validated but no matching ARCOTEL root found',
      warnings,
      chainIncomplete: false,
    };
  }

  // RFC 5280 §4.2.1.3: a document-signing cert must assert digitalSignature
  // or nonRepudiation. A cert that declares keyUsage without either was not
  // issued for signing — reject rather than warn.
  const ku = signerCert.extensions?.find((e) => e.extnID === '2.5.29.15');
  if (ku) {
    // parsedValue is typed loosely; access via any — pkijs typing limitation
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    const kuBytes = new Uint8Array((ku.parsedValue as any).valueBlock.valueHex as ArrayBuffer);
    const firstByte = kuBytes[0] ?? 0;
    // Bit 0 (MSB) = digitalSignature, Bit 1 = nonRepudiation
    if (!(firstByte & 0x80) && !(firstByte & 0x40)) {
      return {
        success: false,
        chain,
        matchedRoot,
        error: 'Signer cert keyUsage does not include digitalSignature or nonRepudiation',
        warnings,
        chainIncomplete: false,
        keyUsageNotSigning: true,
      };
    }
  }

  // Check validity at signing time (pkijs also checks this, but explicit guard here)
  if (!isWithinValidity(signerCert, atTime)) {
    return {
      success: false,
      chain,
      matchedRoot,
      error: `Signer cert not valid at ${atTime.toISOString()}`,
      warnings,
      chainIncomplete: false,
    };
  }

  // Throw on clear trust-anchor violations (belt-and-suspenders after pkijs verify)
  void VerificationError; // imported for future direct throws
  void ERR_CHAIN_FAIL;

  return { success: true, chain, matchedRoot, warnings, chainIncomplete: false };
}
