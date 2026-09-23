---
title: "Security Data electronic signature: how to sign a PDF"
description: "Use your Security Data .p12 or .pfx certificate to sign PDFs free in your browser. Signing steps, passwords, USB tokens and verification explained."
lang: en
datePublished: "2026-05-29"
dateModified: "2026-09-16"
h1: "How to sign a PDF with your Security Data electronic signature"
breadcrumbs:
  - { name: "Security Data electronic signature", url: "https://firmar.ec/en/how-to-sign-with-security-data-certificate/" }
related:
  - { title: "Sign documents online", href: "/en/sign-documents-online/" }
  - { title: "Validate your .p12 certificate", href: "/en/validate-certificate/" }
  - { title: "Electronic certificate prices", href: "/en/pricing/" }
  - { title: "How to verify a PDF signature", href: "/en/verify-pdf-signature/" }
faq:
  - question: "Can I use my Security Data electronic signature in firmar.ec?"
    answer: "Yes, if you have the certificate as a .p12 or .pfx file, its password and a PDF. Select the files in the app and the signature is computed in your browser. This workflow does not support USB tokens or certificates that can only be used in the provider's cloud."
  - question: "Where do I download my Security Data certificate?"
    answer: "Use Security Data's official portal and the instructions for your application. firmar.ec does not issue Security Data certificates or recover their files or passwords."
  - question: "Is my portal password the same as my .p12 password?"
    answer: "Not necessarily. Security Data distinguishes access to its portal from the signature file's password. To sign here, you need the .p12 or .pfx password; if you cannot remember it, follow the issuer's official procedure."
  - question: "Does signing a PDF with my Security Data certificate cost anything?"
    answer: "The firmar.ec web tool lets you sign PDFs free of charge. Buying, renewing or recovering the certificate are separate services whose conditions you should check with Security Data."
---

**To sign a PDF with your Security Data electronic signature, you need the `.p12` or `.pfx` file and its password.** Open firmar.ec, select the PDF, place the visible signature, load the certificate and confirm signing. The PDF and private key are processed in your browser; they are not sent to a signing server.

This guide is for **using a certificate you already have**. To buy, download or renew one, use [Security Data's official channels](https://www.securitydata.net.ec/firma-electronica-en-ecuador/). firmar.ec is a tool independent of that issuer.

[Open the app and sign a PDF](https://app.firmar.ec/firmar)

## What do you need before starting?

- Your valid **`.p12` or `.pfx` certificate file** and its password.
- The document in **PDF** format. If it is in Word, export it to PDF first.
- An up-to-date browser on your computer or phone.

**If you have a USB token, this workflow does not support it.** Do not assume you can export its private key to a file. Use the compatible application and drivers recommended by the issuer. Security Data distinguishes [certificates stored on tokens from certificates in files](https://www.securitydata.net.ec/ayuda-security-data-ecuador/).

## How to sign with Security Data step by step

1. **Open the app.** Visit app.firmar.ec/firmar in your browser.
2. **Select the PDF and place the visible signature.** Choose the page and position of the signature box.
3. **Select your certificate.** Load your Security Data .p12 or .pfx file.
4. **Check the password and sign.** Enter the file's password, review the holder and summary, and press Sign PDF.
5. **Download and verify.** Save the signed PDF and check its signature before submitting it.

You can [validate your certificate](/en/validate-certificate/) before signing to review its holder and validity period. Afterwards, use [Verify PDF](https://app.firmar.ec/verificar) and read our [guide to interpreting the result](/en/verify-pdf-signature/).

## What if the password does not work?

The Security Data portal password and the certificate password are different credentials. Check that you selected the correct file, especially after a renewal. Follow the [official password recovery guide](https://www.securitydata.net.ec/recuperar-clave-firma-electronica/); its conditions depend on your certificate and how you purchased it.

Do not send your `.p12` file or password to someone else to sign on your behalf.

## Can I use the PDF for my procedure?

firmar.ec creates an electronic signature within the PDF. Acceptance depends on the procedure's requirements and the verification result, not just the visible seal. Ask the receiving institution whether it requires a particular platform, format or additional evidence.

Article 14 of the [Electronic Commerce Act published by ARCOTEL](https://www.arcotel.gob.ec/wp-content/uploads/2015/12/ley-comercio-electronico-firmas-electronicas-y-mensaje-de-datos.pdf) recognises the legal effects of electronic signatures; article 15 sets requirements for validity. A signed PDF does not replace the XML of an SRI electronic invoice.

If you do not have a certificate yet, read [how to obtain one](/en/how-to-get-an-electronic-certificate/) and compare [providers' published prices](/en/pricing/).
