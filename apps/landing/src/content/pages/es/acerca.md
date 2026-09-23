---
title: "Acerca de firmar.ec"
description: "Por qué existe firmar.ec, quién está detrás, y por qué es gratis y open-source. Un proyecto de IDK Manager."
lang: es
dateModified: "2026-09-18"
datePublished: "2026-05-08"
h1: "Acerca de firmar.ec"
breadcrumbs:
  - { name: "Acerca", url: "https://firmar.ec/acerca/" }
---

## Por qué existe firmar.ec

Queremos facilitar la firma y revisión de documentos PDF con certificado electrónico desde un navegador, sin que el usuario tenga que enviar su llave privada al servicio. Cada herramienta tiene requisitos y modelos de confianza distintos; nuestra propuesta es hacer explícito el nuestro y permitir su inspección.

firmar.ec resuelve eso con **una PWA pública, gratuita, sin registro, sin tracking, donde tu llave privada nunca sale del navegador**.

## Quién está detrás

firmar.ec es un proyecto **open-source sin fines de lucro** de **[IDK Manager](https://idkmanager.com)**, un taller de software y servicios técnicos en Quito, Ecuador. Construimos y operamos esta herramienta como contribución al ecosistema digital ecuatoriano.

No cobramos por el servicio. No hay plan premium. No hay suscripción. No hay publicidad. No hay telemetría.

El costo de mantenimiento (dominio, hosting, certificados, mantenimiento del código) lo asume IDK Manager. La filosofía que guía el proyecto: **una herramienta crítica de soberanía digital no debería tener fines de lucro**.

## ¿Por qué open-source?

Una herramienta que procesa una llave privada debe poder inspeccionarse. Publicamos el [código fuente y su licencia AGPL-3.0](https://github.com/idkmanager/firmar-ec), las pruebas y las instrucciones de desarrollo. Revisa el código correspondiente a la versión que estés evaluando; una licencia abierta no equivale por sí sola a una auditoría independiente.

Nuestra [metodología para interpretar una verificación](/metodologia-verificacion/) explica qué demuestra cada comprobación y qué límites debes registrar. El [perfil de Alfonso Kuen Arroyo](https://idkmanager.com/equipo/alfonso-kuen-arroyo/) identifica al responsable técnico del proyecto.

## ¿Cómo se sostiene en el tiempo?

- **Código simple y mantenible** (Astro 5 + Svelte 5 + bibliotecas criptográficas de código abierto) — minimiza la deuda técnica acumulada.
- **La app es estática** — se sirve como archivos, sin servidor que la renderice; los costos de hosting son insignificantes. El único backend propio es el de los contadores agregados de uso (ver el aviso de privacidad).
- **Comunidad** — aceptamos issues, PRs, traducciones. Si tu organización quiere contribuir o colaborar, escríbenos.
- **Plan B** — si IDK Manager dejara de operar el servicio, el código sigue disponible en GitHub bajo AGPL-3.0; cualquiera puede continuar la operación con un nuevo dominio.

## Estado del proyecto

Consulta las [versiones publicadas](https://github.com/idkmanager/firmar-ec/releases), el [historial de cambios](https://github.com/idkmanager/firmar-ec/blob/main/CHANGELOG.md) y las [propuestas abiertas](https://github.com/idkmanager/firmar-ec/issues). Son las referencias para distinguir funciones disponibles de trabajo propuesto. Las posibilidades de cada firma dependen de su configuración, del certificado y de la evidencia disponible.

## Contacto

- General / soporte: [GitHub Issues](https://github.com/idkmanager/firmar-ec/issues)
- Datos personales (LOPDP): contacto al controlador IDK Manager en [idkmanager.com/contacto](https://idkmanager.com/contacto/)
- Seguridad (advisory privado): [GitHub Security Advisories](https://github.com/idkmanager/firmar-ec/security/advisories/new)
- GitHub: [github.com/idkmanager/firmar-ec](https://github.com/idkmanager/firmar-ec)
