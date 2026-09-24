import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { toHex } from '@firma-ec/crypto-core';
import { validateTsaCertChain } from '@firma-ec/tsa-trust';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { describe, expect, test } from 'vitest';
import { accreditedTsaAnchors } from '../src/timestamp';

/**
 * tsa-accredited.test.ts — timestamps from any ARCOTEL-accredited ECI are
 * recognised (2026-09-24, "a la par de Security Data").
 *
 * Before, only FreeTSA and the UANATACA ROOT 2016 anchors were trusted for
 * timestamps; a Security Data, BCE or UANATACA EC TSU01 timestamp failed with
 * chain_invalid, so it could not serve as proof of the signing time. The
 * verifier now offers the TSL roots it already pins for signatures.
 */

const derOf = (u8: Uint8Array) => new Certificate({ schema: fromBER(u8.slice().buffer).result });
const sha256Hex = async (c: Certificate) =>
  toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', c.toSchema().toBER(false))));

describe('accredited TSA anchors come from the ARCOTEL TSL', () => {
  test('include the Security Data CA-2 root and the SubCA-2 that issues its TSU', async () => {
    const { anchors, intermediates } = await accreditedTsaAnchors();
    const anchorFps = await Promise.all(anchors.map(sha256Hex));
    // Fingerprint published by Security Data (sellado_tiempo.pdf, SD-ID-PE-12).
    expect(anchorFps).toContain('503b5960fa8cc58f3367642a911fd8f8277e474d6891637fe56ca2a69f069cbd');
    const cns = intermediates.map(
      (c) =>
        (
          c.subject.typesAndValues.find((t) => t.type === '2.5.4.3')?.value.valueBlock as {
            value: string;
          }
        ).value,
    );
    expect(cns).toContain('AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA');
  });

  test('the official UANATACA EC TSU01 certificate validates against them', async () => {
    const der = new Uint8Array(
      readFileSync(
        resolve(__dirname, '../../tsa-trust/tests/__fixtures__/uanataca-ec-tsu01-leaf.der'),
      ),
    );
    const cert = derOf(der);
    const r = await validateTsaCertChain(
      { certificate: cert, der, notBefore: cert.notBefore.value, notAfter: cert.notAfter.value },
      [],
      new Date(),
      await accreditedTsaAnchors(),
    );
    expect(r).toMatchObject({ ok: true });
  });
});
