---
title: "Seguridad y Transparencia"
description: "Reporte de seguridad y transparencia técnica de firmar.ec: modelo de amenazas, controles, auditorías externas, divulgación responsable."
lang: es
dateModified: "2026-09-18"
datePublished: "2026-05-08"
h1: "Seguridad y Transparencia"
breadcrumbs:
  - { name: "Seguridad", url: "https://firmar.ec/seguridad/" }
---

**Versión 1.0** · Última auditoría 2026-05-08

> **¿Es seguro firmar.ec? Sí.** Tu llave privada `.p12` nunca sale de tu equipo: la firma ocurre 100% en tu navegador, dentro de un Web Worker aislado, con la llave importada como `CryptoKey extractable: false` (nunca queda como bytes manipulables en memoria). El código es **open source auditable** (AGPL-3.0) y el sitio obtiene **A+** en Mozilla Observatory (125/100), SSL Labs y securityheaders.com (verificado 2026-05-08). Sin terceros en runtime y sin subir tu PDF ni tu certificado a ningún servidor.

## Resumen del modelo de amenazas

La amenaza principal a contener es la **exfiltración de la llave privada `.p12`** del firmante (XSS, supply-chain, extensión maliciosa). Las decisiones de arquitectura están subordinadas a este objetivo:

- **Web Worker dedicado** para parseo PKCS#12 + firma — terminado al concluir
- **CryptoKey `extractable: false`** importada al Web Crypto API — la llave nunca queda como bytes manipulables en el heap JS
- **CSP estricto** sin `unsafe-inline` script + Trusted Types + COOP/COEP/CORP cross-origin isolation
- **Cero terceros runtime** (sin CDN, sin Google Fonts, sin analytics, sin píxel)
- **SRI hashes** en cada `<script>/<link>`
- **Reproducible builds** — roadmap (toolchain pinneado por digest; verificación externa con `diffoscope` pendiente)

Modelo STRIDE completo en el [spec del proyecto](https://github.com/idkmanager/firmar-ec/blob/main/docs/superpowers/specs/2026-05-08-firma-ec-design.md#4-modelo-de-amenazas-stride-y-controles).

## Auditorías externas vigentes

| Auditoría | Resultado | Última verificación |
|---|---|---|
| [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory/analyze?host=firmar.ec) | **A+ 125/100, 10/10 tests** | 2026-05-08 |
| [securityheaders.com](https://securityheaders.com/?q=https%3A%2F%2Ffirmar.ec) | **A+** | 2026-05-08 |
| [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d=firmar.ec) | **A+** | 2026-05-08 |
| [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/idkmanager/firmar-ec) | en monitoreo continuo | rolling |
| Lighthouse (home) | 100/100/100/100 | en cada release |

## Controles activos

### Transporte
- TLS 1.3 only · HSTS preload · CAA pinning a Let's Encrypt
- DNSSEC activo en zona firmar.ec
- Edge: Cloudflare WAF + rate limit
- Origen: Ecuador (Swarm IDK, Quito) — Cloudflare Tunnel

### Browser
- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script' (en `app.firmar.ec`)`
- COOP `same-origin` + COEP `require-corp` + CORP `same-origin` (cross-origin isolation activado)
- Trusted Types ON en `app.firmar.ec`
- Permissions-Policy: USB, clipboard-write, geolocation, camera, mic, payment todas en `()`

### Supply chain
- Releases firmadas con [Sigstore Cosign](https://www.sigstore.dev/) (keyless via OIDC GitHub Actions)
- Transparency log en [Rekor](https://docs.sigstore.dev/logging/overview/)
- SLSA L2 con elementos L3 (provenance firmada por release, runner GitHub-hosted hardened; L3 estricto pendiente — ver [`SECURITY.md`](https://github.com/idkmanager/firmar-ec/blob/main/SECURITY.md))
- SBOM en CycloneDX 1.6 + SPDX 2.3 publicados con cada release
- Renovate Bot con políticas estrictas: paquetes criptográficos siempre review humano + nota de auditoría

### Operación
- Pentest interno antes de cada release significativo (OWASP ZAP, nuclei, semgrep, trivy, gitleaks)
- Mutation testing (StrykerJS) sobre `crypto-core` y `verifier` packages
- Property-based testing (fast-check) sobre primitivas criptográficas
- Lighthouse CI gate 100/100/100/100 — la PR no merge si baja en home/landing

## Divulgación responsable de vulnerabilidades

Si encuentras un problema de seguridad, agradecemos el reporte privado:

1. Reporta vía [GitHub Security Advisories (privado)](https://github.com/idkmanager/firmar-ec/security/advisories/new) — el canal está cifrado en tránsito y permite coordinar embargo y publicación.
2. Indica: descripción, impacto, pasos para reproducir, versión afectada (release tag o commit SHA)
3. Te respondemos en máximo **48 horas**
4. Coordinamos remediación + ventana de divulgación pública (típicamente 30-90 días según severidad)

Política completa en [/.well-known/security.txt](/.well-known/security.txt) (RFC 9116).

## Hall of Fame

Reconocimiento público a quienes han contribuido a mejorar la seguridad de firmar.ec:

*(Actualmente vacío — sé el primero.)*

## Histórico de incidentes

*(Ninguno reportado a la fecha — actualizado en cada incidente.)*

## Modo paranoia

Para verificar tú mismo que tu llave nunca sale del navegador, sigue las instrucciones de [/paranoia](https://app.firmar.ec/paranoia) en la app.

## Interpretar los resultados

Consulta la [metodología de verificación de firmas PDF](/metodologia-verificacion/): integridad, confianza, revocación y tiempo son comprobaciones distintas. Incluye una lista para documentar la revisión y sus límites.
