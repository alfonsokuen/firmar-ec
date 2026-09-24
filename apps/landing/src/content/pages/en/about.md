---
title: "About firmar.ec"
description: "Why firmar.ec exists, who is behind it, and why it is free and open-source. A project by IDK Manager."
lang: en
dateModified: "2026-09-18"
datePublished: "2026-05-08"
h1: "About firmar.ec"
breadcrumbs:
  - { name: "About", url: "https://firmar.ec/en/about/" }
---

## Why firmar.ec exists

We want to make certificate-based PDF signing and review accessible from a browser without sending the private key to the service. Tools have different requirements and trust models; our approach is to make ours explicit and inspectable.

firmar.ec solves this with **a public, free, registration-free, tracking-free PWA where your private key never leaves the browser**.

## Who is behind it

firmar.ec is a **non-profit open-source project** by **[IDK Manager](https://idkmanager.com)**, a software and technical services workshop in Quito, Ecuador. We build and operate this tool as a contribution to Ecuador's digital ecosystem.

We charge nothing for the service. There is no premium plan. No subscription. No advertising. No telemetry.

The cost of maintenance (domain, hosting, certificates, code upkeep) is borne by IDK Manager. The guiding philosophy: **a critical digital sovereignty tool should not be profit-driven**.

## Why open-source?

A tool that processes a private key should be inspectable. We publish the [source code and AGPL-3.0 licence](https://github.com/idkmanager/firmar-ec), tests and development instructions. Inspect the code for the version you are evaluating; an open licence alone does not constitute an independent audit.

Our [verification methodology](/en/verification-methodology/) explains what each check demonstrates and which limitations to record. [Alfonso Kuen Arroyo’s profile](https://idkmanager.com/equipo/alfonso-kuen-arroyo/) identifies the project’s technical lead.

## How does it stay sustainable?

- **Simple, maintainable code** (Astro 5 + Svelte 5 + open-source cryptographic libraries) — minimises accumulated technical debt.
- **Static application** — the app is served as files. An owned backend provides aggregate usage counters; see the privacy notice.
- **Community** — we accept issues, PRs, and translations. If your organisation wants to contribute or collaborate, get in touch.
- **Plan B** — if IDK Manager were to stop operating the service, the code remains available on GitHub under AGPL-3.0; anyone can continue operations under a new domain.

## Project status

Consult the [published releases](https://github.com/idkmanager/firmar-ec/releases), [changelog](https://github.com/idkmanager/firmar-ec/blob/main/CHANGELOG.md) and [open proposals](https://github.com/idkmanager/firmar-ec/issues) to distinguish available features from proposed work. Each signature’s capabilities depend on its configuration, certificate and available evidence.

## Contact

- General / support: [GitHub Issues](https://github.com/idkmanager/firmar-ec/issues)
- Personal data (LOPDP): contact the controller IDK Manager at [idkmanager.com/contacto](https://idkmanager.com/contacto/)
- Security (private advisory): [GitHub Security Advisories](https://github.com/idkmanager/firmar-ec/security/advisories/new)
- GitHub: [github.com/idkmanager/firmar-ec](https://github.com/idkmanager/firmar-ec)
