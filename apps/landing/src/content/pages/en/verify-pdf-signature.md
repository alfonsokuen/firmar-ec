---
title: "How to verify a PDF signature in Ecuador"
description: "Check whether a signed PDF is valid: document integrity, a certificate from an ARCOTEL-accredited ECI, and revocation status. In your browser, with no install."
lang: en
dateModified: "2026-09-18"
datePublished: "2026-05-25"
h1: "How to verify the electronic signature of a PDF"
breadcrumbs:
  - { name: "Verify a PDF signature", url: "https://firmar.ec/en/verify-pdf-signature/" }
related:
  - { title: "What is PAdES?", href: "/en/what-is-pades-signature/" }
  - { title: "Electronic signatures in Ecuador", href: "/en/electronic-signature-ecuador/" }
  - { title: "How to sign with a BCE certificate", href: "/en/how-to-sign-with-bce-certificate/" }
---

> **How do you check that a signed PDF is valid in Ecuador?** Upload the PDF to the verifier at [app.firmar.ec/verify](https://app.firmar.ec/#/verificar): it checks three things in your browser — that the **document was not altered** after signing, that the **certificate** comes from an Information Certification Entity (ECI) accredited by ARCOTEL, and its **revocation status** (OCSP/CRL). It's free, you install nothing, and the file is never uploaded to a server.

## What does a "valid" signature mean?

An electronic signature on a PDF is valid in Ecuador when **three conditions** hold at once:

1. **Integrity** — the PDF content did not change by a single byte after signing. If someone edits it after the signature, verification fails.
2. **Trusted certificate** — the signer's certificate was issued by an **ECI accredited by ARCOTEL**. A signature with a valid certificate has the same legal validity as a handwritten one (Law of Electronic Commerce, LCE 2002-67).
3. **Validity / non-revocation** — the certificate was **valid and not revoked** at signing time. This is checked against the CA's service (real-time OCSP, or CRL lists).

## How to verify, step by step

1. Open the verifier at [app.firmar.ec/verify](https://app.firmar.ec/#/verificar).
2. Drag or select the **signed PDF** you want to check.
3. Read the result: **signer, issuing CA, signing date, integrity** and certificate status.
4. *(Optional)* If the document carries a **visible stamp with a QR code**, scan it: the QR links to the verifier with the document hash (`verify?h=<hash>`) to check it directly.

The whole process happens **in your browser**: the PDF never travels to any server.

## What the verifier tells you

- Who signed (the certificate holder's name) and which **Ecuadorian CA** issued it.
- Whether the document's **integrity** is intact.
- The signature's **PAdES profile** (B-B, B-T, B-LT or B-LTA) and, if it carries a **timestamp** (TSA, RFC 3161), the certified date.
- The certificate's **revocation** status (OCSP/CRL).

## What if I don't use firmar.ec?

You can also verify a PAdES signature in **Adobe Acrobat Reader** (signature panel) or in the **official MINTEL validator** ([minka.gob.ec](https://minka.gob.ec)). A PDF signed in firmar.ec validates correctly in any of them, and vice versa: they all produce and read the same **PAdES Baseline** technical profile (ETSI EN 319 142).

## Frequently asked questions

**Do I need to install anything to verify?** No. The firmar.ec verifier works in any modern browser, including on mobile.

**Does verification work offline?** The integrity check and the certificate chain do; real-time revocation checks (OCSP) require a connection.

**I received a PDF and it says "invalid signature" — what should I do?** This usually means the document was edited after signing, or the certificate was expired/revoked at signing time. Ask the sender to re-sign the final document.

## Interpreting results

See the [PDF signature verification methodology](/en/verification-methodology/): integrity, trust, revocation and time are separate checks. It includes a checklist for documenting a review and its limitations.
