---
title: "Security and Transparency"
description: "Security and technical transparency report for firmar.ec: threat model, controls, external audits, and responsible disclosure."
lang: en
dateModified: "2026-09-18"
datePublished: "2026-05-08"
h1: "Security and Transparency"
breadcrumbs:
  - { name: "Security", url: "https://firmar.ec/en/security/" }
---

**Version 1.0** · Last audit 2026-05-08

> **Is firmar.ec secure? Yes.** Your private `.p12` key never leaves your device: signing happens 100% in your browser, inside an isolated Web Worker, with the key imported as a `CryptoKey` with `extractable: false` (it never exists as manipulable bytes in memory). The code is **auditable open source** (AGPL-3.0) and the site scores **A+** on Mozilla Observatory (125/100), SSL Labs and securityheaders.com (verified 2026-05-08). No runtime third parties, and your PDF and certificate are never uploaded to any server.

## Threat model summary

The primary threat to contain is the **exfiltration of the signer's `.p12` private key** (XSS, supply-chain attack, malicious extension). Architectural decisions are subordinate to this goal:

- **Dedicated Web Worker** for PKCS#12 parsing + signing — terminated upon completion
- **`CryptoKey extractable: false`** imported into the Web Crypto API — the key never exists as manipulable bytes on the JS heap
- **Strict CSP** without `unsafe-inline` scripts + Trusted Types + COOP/COEP/CORP cross-origin isolation
- **Zero runtime third parties** (no CDN, no Google Fonts, no analytics, no pixel)
- **SRI hashes** on every `<script>/<link>`
- **Reproducible builds** — roadmap (toolchain pinned by digest; external `diffoscope` verification pending)

Full STRIDE model in the [project spec](https://github.com/idkmanager/firmar-ec/blob/main/docs/superpowers/specs/2026-05-08-firma-ec-design.md#4-modelo-de-amenazas-stride-y-controles).

## Current external audits

| Audit | Result | Last verified |
|---|---|---|
| [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory/analyze?host=firmar.ec) | **A+ 125/100, 10/10 tests** | 2026-05-08 |
| [securityheaders.com](https://securityheaders.com/?q=https%3A%2F%2Ffirmar.ec) | **A+** | 2026-05-08 |
| [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d=firmar.ec) | **A+** | 2026-05-08 |
| [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/idkmanager/firmar-ec) | continuous monitoring | rolling |
| Lighthouse (home) | 100/100/100/100 | every release |

## Active controls

### Transport
- TLS 1.3 only · HSTS preload · CAA pinning to Let's Encrypt
- DNSSEC active on the firmar.ec zone
- Edge: Cloudflare WAF + rate limiting
- Origin: Ecuador (IDK Swarm, Quito) — Cloudflare Tunnel

### Browser
- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script' (on app.firmar.ec)`
- COOP `same-origin` + COEP `require-corp` + CORP `same-origin` (cross-origin isolation enabled)
- Trusted Types ON on `app.firmar.ec`
- Permissions-Policy: USB, clipboard-write, geolocation, camera, mic, payment all set to `()`

### Supply chain
- Releases signed with [Sigstore Cosign](https://www.sigstore.dev/) (keyless via OIDC GitHub Actions)
- Transparency log in [Rekor](https://docs.sigstore.dev/logging/overview/)
- SLSA L2 with L3 elements (signed provenance per release, hardened GitHub-hosted runner; strict L3 pending — see [`SECURITY.md`](https://github.com/idkmanager/firmar-ec/blob/main/SECURITY.md))
- SBOM in CycloneDX 1.6 + SPDX 2.3 published with each release
- Renovate Bot with strict policies: cryptographic packages always require human review + audit note

### Operations
- Internal pentest before each significant release (OWASP ZAP, nuclei, semgrep, trivy, gitleaks)
- Mutation testing (StrykerJS) on `crypto-core` and `verifier` packages
- Property-based testing (fast-check) on cryptographic primitives
- Lighthouse CI gate 100/100/100/100 — PRs do not merge if home/landing scores drop

## Responsible vulnerability disclosure

If you find a security issue, we welcome a private report:

1. Report via [GitHub Security Advisories (private)](https://github.com/idkmanager/firmar-ec/security/advisories/new) — the channel is encrypted in transit and lets us coordinate embargo and disclosure.
2. Include: description, impact, reproduction steps, affected version (release tag or commit SHA)
3. We respond within **48 hours**
4. We coordinate remediation + public disclosure window (typically 30-90 days depending on severity)

Full policy at [/.well-known/security.txt](/.well-known/security.txt) (RFC 9116).

## Hall of Fame

Public recognition for those who have helped improve firmar.ec's security:

*(Currently empty — be the first.)*

## Incident history

*(No incidents reported to date — updated on each incident.)*

## Paranoia mode

To verify yourself that your key never leaves the browser, follow the instructions at [/paranoia](https://app.firmar.ec/paranoia) in the app.

## Interpreting results

See the [PDF signature verification methodology](/en/verification-methodology/): integrity, trust, revocation and time are separate checks. It includes a checklist for documenting a review and its limitations.
