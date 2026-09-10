# firmar.ec

> Firmador web de PDFs para Ecuador. 100% open source (AGPL-3.0), 100% del lado del cliente. Tu `.p12` nunca sale del navegador.

[![App](https://img.shields.io/badge/app-firmar.ec-0F172A?style=flat-square)](https://app.firmar.ec)
[![Mozilla Observatory](https://img.shields.io/badge/Mozilla_Observatory-A%2B-success?style=flat-square)](https://observatory.mozilla.org/analyze/firmar.ec)
[![SSL Labs](https://img.shields.io/badge/SSL_Labs-A%2B-success?style=flat-square)](https://www.ssllabs.com/ssltest/analyze.html?d=firmar.ec)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)

## ¿Qué es?

Una PWA que firma y verifica PDFs con certificado digital `.p12` emitido por las ACEs acreditadas por **ARCOTEL**. Toda la criptografía corre en el navegador (Web Crypto + WebAssembly); el archivo y la llave nunca tocan un servidor.

- **App**: <https://app.firmar.ec>
- **Sitio institucional**: <https://firmar.ec>
- **Comparación honesta vs FirmaEC (MINTEL)**: [`docs/COMPARATIVA.md`](docs/COMPARATIVA.md)

> **Sobre el panorama OSS en Ecuador**: FirmaEC del MINTEL también es open-source (publicada en [MINKA](https://minka.gob.ec)). firmar.ec **no es la única OSS**; es la primera **web/PWA** OSS auditable con foco en privacidad client-side estricta. Ambas son complementarias — ver comparativa.

![PWA home](docs/screenshots/pwa-home.png)

## Estado del proyecto

> **Versión actual**: landing `v0.1.36` · PWA `v0.9.2` (mayo 2026). La herramienta de firma/verificación es y seguirá siendo **gratis y open source**.

| Fase  | Descripción                                              | Estado                              |
| ----- | -------------------------------------------------------- | ----------------------------------- |
| F1    | Landing pública (firmar.ec)                              | ✅ LIVE — v0.1.36                   |
| F2    | Verificación PDF (PAdES B-B)                             | ✅ LIVE                             |
| F3    | Firma con `.p12` (PAdES B-B + cuadro QR estilo FirmaEC)  | ✅ LIVE — v0.5.1                    |
| F4    | Hardening (Mozilla A+, SSL Labs A+, CSP estricta)        | ✅ LIVE                             |
| F6    | Sello de tiempo (RFC 3161, FreeTSA) → PAdES B-T          | ✅ LIVE — v0.6.0                    |
| F7    | LTV (DSS + OCSP + document timestamp) → PAdES B-LT/B-LTA | ✅ LIVE — v0.7.0-rc1                |
| —     | Contador de uso en vivo (Cloudflare Worker + KV, sin PII) + cluster de contenido SEO bilingüe ES/EN | ✅ LIVE — landing v0.1.36 |
| F3.5  | WhatsApp inbox/outbox bidireccional                      | 🟡 Código completo, deploy pendiente |
| F8    | Multi-firmante con flujo (workflow orchestration)        | ⏳ Scope abierto                    |

## Características LIVE

- **Firma local** — `.p12` jamás sale del navegador. Web Crypto + node-forge (`.p12` legacy 3DES).
- **Perfiles PAdES** — B-B, **B-T** (TSA), **B-LT** (DSS+OCSP+CRL), **B-LTA** (document timestamp).
- **Verificación offline** — TSL local con **17 ACEs ARCOTEL** ancladas (SHA-256 + SRI).
- **Compatible** — firmas verificables en Adobe Reader, FirmaEC y MINKA (MINTEL).
- **PWA instalable** — funciona offline. Share Target API: recibe PDFs desde WhatsApp/Gmail.
- **Cuadro de firma con QR** — 240×72pt, URL `firmar.ec/#/verificar?h=<hash>`.
- **3 modos**: Firmar, Verificar, Paranoia (verificación estricta sin red).
- **Contador de uso en vivo** — la landing muestra cifras reales (documentos firmados · firmas verificadas) servidas por un Cloudflare Worker + KV, **sin PII** (solo enteros, rate-limit por IP), alineado con la postura zero-knowledge / LOPDP.

## API de verificación (`api.firmar.ec`)

Verificación PAdES por HTTP, contra las mismas anclas de confianza de las
entidades de certificación acreditadas del Ecuador que usa la app.

```bash
curl -X POST https://api.firmar.ec/v1/verify \
  -H "Authorization: Bearer fev_live_..." \
  -H "Content-Type: application/pdf" \
  --data-binary @documento.pdf
```

- **Nunca recibe claves privadas.** Verificar solo necesita el material público
  que ya viaja dentro del documento; no hay ningún endpoint que acepte un `.p12`.
- **Distingue "no pude" de "no vale".** `422` significa que el documento no se
  pudo procesar; `502`, que falló *nuestro* motor. Colapsar ambos en un veredicto
  es exactamente el fallo que esta API está construida para no cometer.
- **Íntegro no es lo mismo que confiable.** Un PDF sin alterar cuyo firmante no
  encadena a una EC acreditada sale `invalid`, no `valid`.
- Contrato completo: [`/v1/openapi.json`](https://api.firmar.ec/v1/openapi.json).

**Cómo se paga.** El *software* es libre: despliégalo en tu propia
infraestructura bajo AGPL-3.0, sin costo y sin que tus documentos salgan de tu
red. La **API alojada es un servicio de pago**, porque consume infraestructura y
operación de IDK Manager. Hay una **prueba de 30 días** (50 verificaciones al
día) que caduca sola; para producción, el volumen se acuerda por contrato:
**info@idkmanager.com**.

## Qué NO hace (out of scope hoy)

- **XAdES / comprobantes SRI** — el SRI usa XAdES, no PAdES; usa FirmaEC del MINTEL.
- **Tokens USB criptográficos** — solo `.p12` (WebUSB en evaluación).
- **Firma en lote** — un PDF a la vez (roadmap F8 contempla flujos).
- **Quipux integración nativa** — testable manualmente; sin workflow oficial.

### Capturas

| Vista                    | Imagen                                                         |
| ------------------------ | -------------------------------------------------------------- |
| Landing — desktop        | ![landing desktop](docs/screenshots/landing-home-desktop.png)  |
| Landing — móvil          | ![landing mobile](docs/screenshots/landing-home-mobile.png)    |
| PWA — Firmar (paso 1)    | ![firmar](docs/screenshots/pwa-firmar-step1.png)               |
| PWA — Verificar (paso 1) | ![verificar](docs/screenshots/pwa-verificar-step1.png)         |
| PWA — Paranoia           | ![paranoia](docs/screenshots/pwa-paranoia.png)                 |
| PWA — Acerca             | ![about](docs/screenshots/pwa-about.png)                       |

## Stack

- **Landing**: Astro 5 + UnoCSS + tokens compartidos (`@firma-ec/ui-tokens`).
- **PWA**: Svelte 5 (runes) + Vite 6 + UnoCSS + svelte-spa-router.
- **Crypto**: pkijs 3.x + asn1js + node-forge (3DES legacy) + @noble/curves + Web Crypto.
- **PDF**: pdf-lib + @signpdf v3.3.0 + pdfjs-dist v4.
- **Tests**: Vitest + fast-check + Playwright + Stryker.
- **Infra**: Docker Swarm IDK + Caddy 2 + Cloudflare Tunnel.

## Privacidad y seguridad

- Sin telemetría. Sin analytics de terceros.
- CSP estricta (sin `unsafe-inline` en scripts, sin `eval`).
- Service Worker custom intercepta `/share` para evitar enviar PDF al servidor.
- 17 raíces ARCOTEL ancladas con SHA-256 y verificación SRI.
- Threat model y críticas UI Pro Max disponibles bajo [`docs/`](docs/).
- Política de divulgación responsable: [`SECURITY.md`](SECURITY.md).
- Reportes privados: [GitHub Security Advisories](https://github.com/idkmanager/firmar-ec/security/advisories/new).

## Supply chain (SLSA L2 con elementos L3)

Resumen ejecutivo — assessment completo en [`docs/slsa-conformance.md`](docs/slsa-conformance.md).

- **Build Track L2 (verificado)**: provenance signed via `actions/attest-build-provenance@v2`, cosign keyless OIDC, Rekor public tlog, SBOM CycloneDX 1.6 + SPDX 2.3.
- **L3 elements cumplidos**: ephemeral runner, non-falsifiable provenance, service-generated attestations.
- **L3 strict gaps**: (a) hermeticidad — `pnpm install` aún accede al registry npm; (b) Source Track L3 requiere branch protection con 2-reviewer review (decisión pendiente — hoy somos solo-maintainer); (c) auditoría externa independiente del build platform.
- **Verificación pública**: `gh attestation verify --owner idkmanager --signer-workflow .github/workflows/release.yml <artifact>`.

## Reproducible Builds (roadmap, quick wins aplicados)

Estado completo + verificación local en [`docs/reproducible-builds.md`](docs/reproducible-builds.md).

- **Aplicado 2026-05-10**: `SOURCE_DATE_EPOCH` desde commit timestamp, `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@$SDE`, `gzip -n` (strips embedded mtime/filename).
- **Pendiente verificación bit-idéntica**: confirmar que dos runs back-to-back producen el mismo `sha256` (CI job a añadir).
- **Pendiente cross-environment**: rebuild desde otra distro / runner.
- **Verificación externa**: si lo intentas, abre un issue con el report de `diffoscope` — agradecemos cualquier verificación independiente.

## Verificar releases con Sigstore

Public key:    <https://firmar.ec/.well-known/cosign.pub>
Latest tag:    `v0.7.0-rc1`
Tag SHA:       `9380db41291f2beadf2f3304cecf1d322963679f`
Rekor tlog:    `1497932420` · integrated `2026-05-10T19:02:23 UTC`
Sig + bundle:  `_backups/F7-deploy-2026-05-10-rc1/v0.7.0-rc1.{sig,bundle}`

```bash
# 1. Fetch the public key
curl -sf https://firmar.ec/.well-known/cosign.pub -o cosign.pub

# 2. Pin the tag SHA you want to verify
TAG="v0.7.0-rc1"
TAG_SHA=$(git rev-parse "$TAG")
echo "$TAG_SHA"  # debería imprimir 9380db41291f2beadf2f3304cecf1d322963679f

# 3. Verify the signature against the tag SHA
cosign verify-blob \
  --key cosign.pub \
  --signature _backups/F7-deploy-2026-05-10-rc1/v0.7.0-rc1.sig \
  --bundle    _backups/F7-deploy-2026-05-10-rc1/v0.7.0-rc1.bundle \
  --rekor-url https://rekor.sigstore.dev \
  <(echo -n "$TAG_SHA")

# 4. Cross-check Rekor tlog entry
rekor-cli get --log-index 1497932420 --rekor_server https://rekor.sigstore.dev
```

Si cualquier paso falla, **no confíes en el binario** y abre un issue.

## Principios

Segura · Fácil de usar · Ligera · Compatible · Mobile-first · Fully responsive · Privacy by design · LOPDP-native · Open source · Auditable.

## Desarrollo local

```bash
git clone https://git.idkmanager.com/alfonso/firmar-ec
cd firma-ec
pnpm install
pnpm -F @firma-ec/landing dev   # http://localhost:4321
pnpm -F @firma-ec/pwa dev       # http://localhost:5173
pnpm test                       # all packages
```

## Patrocinio

firmar.ec es y seguirá siendo gratis. El patrocinio no compra el servicio:
financia el desarrollo, las auditorías de seguridad y la infraestructura que
mantienen la herramienta viva y abierta.

| Tier | Mensual | Anual (10% desc.) | Target |
|------|---------|-------------------|--------|
| 🥉 Bronze   | $50    | $540    | Freelancers, devs, microempresas |
| 🥈 Silver   | $200   | $2 160  | Estudios contables, PYMEs, notarías |
| 🥇 Gold     | $500   | $5 400  | Empresas medianas, cooperativas, estudios jurídicos |
| 💎 Platinum | $1 500 | $16 200 | Corporativos, banca, aseguradoras |
| 🏛️ Founding | $5 000+ | Negociable | Instituciones, gobierno, GADs, universidades |

**Pago directo, sin intermediarios**: transferencia bancaria a IDK Manager
Cía. Ltda. con factura SRI. No usamos plataformas que retengan fondos ni
cobren comisión. Escríbenos a **sponsors@firmar.ec** o visita
[firmar.ec/patrocinar](https://firmar.ec/patrocinar).

- Beneficios por tier → [`docs/sponsorship/benefits.md`](docs/sponsorship/benefits.md)
- Gobernanza del programa → [`docs/sponsorship/governance.md`](docs/sponsorship/governance.md)
- Lista de patrocinadores → [`SPONSORS.md`](SPONSORS.md)

## Repos

- **Source**: [git.idkmanager.com/alfonso/firmar-ec](https://git.idkmanager.com/alfonso/firmar-ec)
- **Mirror (org)**: [github.com/idkmanager/firmar-ec](https://github.com/idkmanager/firmar-ec)
- **Mirror (personal)**: [github.com/alfonsokuen/firmar-ec](https://github.com/alfonsokuen/firmar-ec)

## Licencia

firmar.ec usa **licenciamiento dual**:

- **Open source — GNU AGPL-3.0** (ver [`LICENSE`](LICENSE)): libre para usar, estudiar, modificar y redistribuir. Su *copyleft* exige que, si integras o modificas firmar.ec en un sistema que ofreces a terceros (incluido como servicio en red), publiques el código fuente completo de ese sistema bajo AGPL-3.0.
- **Licencia comercial** (ver [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)): para **integrar firmar.ec en productos o servicios propietarios/cerrados con fines de lucro sin liberar tu código**, o para integraciones de empresa/gobierno con SLA, soporte, API o emisión de certificados. Contacto: **info@idkmanager.com**.

Usar la app web tal cual (firmar/verificar) es y seguirá siendo **gratis**, también para empresas e instituciones.

## Créditos

Desarrollado por [IDKmanager](https://idkmanager.com) (Ecuador).

### Autor

Creado por **[Alfonso Kuen Arroyo](https://idkmanager.com/equipo/alfonso-kuen-arroyo/)** — Founder & Technology Architect en IDK MANAGER.

[Perfil](https://idkmanager.com/equipo/alfonso-kuen-arroyo/) · [GitHub](https://github.com/alfonsokuen) · [LinkedIn](https://www.linkedin.com/in/alfonso-kuen-arroyo-5a7a92133)
