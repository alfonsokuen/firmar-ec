---
title: "PDF signature verification methodology | firmar.ec"
description: "A technical checklist for PDF signature integrity, certificate trust, revocation and timestamps, with inspectable sources and implementation."
lang: en
datePublished: "2026-09-18"
h1: "How to interpret PDF signature verification"
breadcrumbs:
  - { name: "Verification methodology", url: "https://firmar.ec/en/verification-methodology/" }
related:
  - { title: "Use the verifier step by step", href: "/en/verify-pdf-signature/" }
  - { title: "Security and trust model", href: "/en/security/" }
---

**Cryptographic integrity alone does not answer every question about a document.** This methodology separates four checks: integrity, certificate trust, revocation and time evidence. Use it to document a technical review and make unresolved checks explicit.

Prepared by **IDK Manager Team**, operator of firmar.ec. [Meet the project's technical lead, Alfonso Kuen Arroyo](https://idkmanager.com/equipo/alfonso-kuen-arroyo/). Edition: 18 September 2026. This is technical guidance, not a legal opinion, conformity certification or accreditation of the verifier.

## 1. Integrity: which bytes the signature protects

Check the digest and signature value over the bytes identified by `ByteRange`. Review each signature separately: a PDF may contain multiple signatures and incremental revisions.

- **Record:** integrity outcome, covered bytes, total size and warnings about later revisions.
- **Do not infer:** that a signature automatically protects anything appended afterwards. An incremental update needs interpretation; its presence alone does not establish fraud.

The engine separates these checks in [integrity.ts](https://github.com/idkmanager/firmar-ec/blob/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier/src/integrity.ts). A visible signature image or stamp does not replace cryptographic verification.

## 2. Certificate and identity: the trust policy matters

Record the subject, issuer, serial number, SHA-256 fingerprint, validity period and trust anchor. Check that the chain reaches a root accepted under the recipient's policy. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) describes X.509 path validation; tools can use different trust stores or policies.

A name extracted from a certificate does not by itself establish the signer's authority to represent an organisation. An unrecognised root does not prove the PDF was altered: first determine whether an intermediate is missing or the policy does not trust that issuer.

For Ecuadorian issuers, consult [ARCOTEL's certification entity information](https://www.arcotel.gob.ec/entidades-de-certificacion-firma-electronica/). Inclusion in an application's trust store is not regulatory accreditation.

## 3. Revocation: unknown does not mean good

Record the OCSP/CRL state, check time and evidence source. The engine distinguishes `good`, `revoked`, `unknown` and `not_checked`, with live, cached, embedded or absent sources.

A blocked request, unavailable responder or offline check can leave revocation unresolved. **Do not turn that outcome into “not revoked”.** An OCSP `good` result does not replace chain, validity-period or integrity checks. See [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) for protocol semantics.

## 4. Time: a claimed date versus verified evidence

Separate the signer's claimed date from a timestamp. For a timestamp, check the message imprint, token signature and TSA trust. The presence of a token does not establish that those checks passed. [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) specifies the timestamp protocol.

PAdES B-B, B-T, B-LT and B-LTA include different elements, described in [ETSI EN 319 142-1, edition 1.2.1](https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf). Detecting a profile or counting embedded responses does not by itself prove all evidence is valid. Review errors and warnings too.

## Checklist to retain with the report

1. Original file identification and SHA-256; keep the PDF without printing or resaving it.
2. Review date and time zone, tool, version and network configuration.
3. Number of signatures, individual results and later revisions for each signature.
4. Issuer, certificate fingerprint, chain and root used; the recipient's trust policy.
5. Revocation state, source and date; explicitly record unknown or unchecked states.
6. Claimed date, presence and result of the TSA timestamp; available time evidence.
7. Complete warnings, limitations and reasons for discrepancies with another tool.

**Example wording:** “Integrity checked; revocation not checked because the connection was unavailable; claimed signing time without a validated timestamp.” This describes the evidence more clearly than a single “valid”. It is an illustration, not a result obtained from a tested document.

## Reproducing and comparing a review

Use the same PDF and record its hash before comparing tools. State the version, review time, trust roots and network requests. Compare each dimension separately: a trust discrepancy is not an integrity discrepancy. Do not publish documents, passwords or private keys when reporting a problem.

This edition is based on the [verifier source at revision 6907d3d](https://github.com/idkmanager/firmar-ec/tree/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier): `index.ts` coordinates the checks; `result.ts` defines the states; `pathValidation.ts`, `timestamp.ts` and `ltv.ts` expose checks and limitations. The [public tests at that revision](https://github.com/idkmanager/firmar-ec/tree/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier/tests) make covered cases inspectable. Their existence does not certify every document, issuer or possible scenario.

For practical steps, see the [verifier guide](/en/verify-pdf-signature/). To report a reproducible discrepancy, use the [project channels](/en/about/).

## Cite this resource

IDK Manager Team. “How to interpret PDF signature verification”. firmar.ec, 18 September 2026. https://firmar.ec/en/verification-methodology/. Include your access date when adapting this checklist for an internal procedure.
