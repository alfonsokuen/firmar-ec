---
title: "Metodología para revisar firmas PDF | firmar.ec"
description: "Lista técnica para interpretar integridad, cadena, revocación y sellos de tiempo de un PDF firmado, con fuentes y código verificables."
lang: es
datePublished: "2026-09-18"
h1: "Cómo interpretar la verificación de una firma PDF"
breadcrumbs:
  - { name: "Metodología de verificación", url: "https://firmar.ec/metodologia-verificacion/" }
related:
  - { title: "Usar el verificador paso a paso", href: "/verificar-firma-pdf/" }
  - { title: "Seguridad y modelo de confianza", href: "/seguridad/" }
---

**Una firma criptográficamente íntegra no resuelve por sí sola todas las preguntas sobre un documento.** Esta metodología separa cuatro comprobaciones: integridad, confianza del certificado, revocación y evidencia temporal. Sirve para documentar una revisión técnica y explicar qué sigue sin comprobarse.

Elaborado por **Equipo IDK Manager**, operador de firmar.ec. [Conoce al responsable técnico del proyecto, Alfonso Kuen Arroyo](https://idkmanager.com/equipo/alfonso-kuen-arroyo/). Edición del 18 de septiembre de 2026. Es una guía técnica; no es un dictamen jurídico, una certificación de conformidad ni una acreditación del verificador.

## 1. Integridad: qué bytes protege la firma

Comprueba el resumen criptográfico y el valor de la firma sobre los bytes indicados por `ByteRange`. Revisa cada firma por separado: un PDF puede contener varias firmas y revisiones incrementales.

- **Registrar:** resultado de integridad, bytes cubiertos, tamaño total y advertencias sobre revisiones posteriores.
- **No concluir:** que una firma protege automáticamente cualquier contenido añadido después. Una actualización incremental necesita interpretación; su presencia aislada tampoco demuestra fraude.

El motor separa estas comprobaciones en [integrity.ts](https://github.com/idkmanager/firmar-ec/blob/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier/src/integrity.ts). La imagen visible de una firma o un sello no sustituye la comprobación criptográfica.

## 2. Certificado e identidad: contra qué confianza se valida

Registra el sujeto, emisor, número de serie, huella SHA-256, vigencia y raíz de confianza utilizada. Revisa que la cadena alcance una raíz aceptada por la política del receptor. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) describe la validación de rutas X.509; dos herramientas pueden usar almacenes o políticas distintos.

Un nombre extraído del certificado no acredita por sí solo las facultades de representación del firmante. Que una raíz no se reconozca tampoco demuestra que el PDF esté alterado: identifica primero si falta un certificado intermedio o si la política no confía en ese emisor.

Para contrastar al emisor en Ecuador, consulta la información oficial de [entidades de certificación de ARCOTEL](https://www.arcotel.gob.ec/entidades-de-certificacion-firma-electronica/). No confundas la inclusión en el almacén de una aplicación con una acreditación emitida por el regulador.

## 3. Revocación: desconocido no significa vigente

Anota el estado OCSP/CRL, la fecha de comprobación y la procedencia de la evidencia. El resultado del motor distingue `good`, `revoked`, `unknown` y `not_checked`, y fuentes en línea, en caché, embebidas o ausentes.

Una consulta bloqueada, un servidor sin respuesta o una revisión sin conexión pueden dejar el estado sin resolver. **No conviertas ese resultado en «no revocado».** Un estado OCSP `good` tampoco sustituye la validación de cadena, vigencia o integridad. Consulta [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) para la semántica del protocolo.

## 4. Tiempo: fecha declarada frente a evidencia verificable

Separa la fecha declarada por el firmante de un sello de tiempo. Para este último, revisa la correspondencia del resumen, la firma del token y la confianza de la TSA. Que exista un token no demuestra que esas comprobaciones hayan pasado. [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) define el protocolo de sellado temporal.

Los perfiles PAdES B-B, B-T, B-LT y B-LTA incorporan distintos elementos, descritos en [ETSI EN 319 142-1, edición 1.2.1](https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf). Detectar un perfil o contar respuestas embebidas no demuestra por sí solo que toda la evidencia sea válida. Revisa también sus errores y advertencias.

## Lista para conservar junto al informe

1. Identificación del archivo original y su SHA-256; conserva el PDF sin reimprimirlo ni volverlo a guardar.
2. Fecha y zona horaria de revisión, herramienta, versión y configuración de red.
3. Número de firmas; resultado individual y revisiones posteriores de cada una.
4. Emisor, huella del certificado, cadena y raíz utilizada; política de confianza del receptor.
5. Estado de revocación, fuente y fecha; deja explícito lo desconocido o no comprobado.
6. Fecha declarada, presencia y resultado del sello TSA; evidencia temporal disponible.
7. Advertencias completas, limitaciones y motivo de cualquier discrepancia con otra herramienta.

**Ejemplo de redacción:** «Integridad comprobada; revocación no comprobada por falta de conexión; fecha declarada sin sello de tiempo validado». Describe mejor la evidencia que un único «válido». Este ejemplo es ilustrativo, no el resultado de un documento ensayado.

## Cómo reproducir y contrastar una revisión

Usa el mismo PDF y registra su hash antes de comparar herramientas. Mantén explícitas la versión, la fecha de revisión, las raíces de confianza y las consultas de red. Contrasta los resultados por dimensión: una divergencia de confianza no equivale a una divergencia de integridad. No publiques documentos, contraseñas ni claves privadas al comunicar un error.

Esta edición se basa en el [código del verificador, revisión 6907d3d](https://github.com/idkmanager/firmar-ec/tree/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier): `index.ts` coordina la revisión; `result.ts` define sus estados; `pathValidation.ts`, `timestamp.ts` y `ltv.ts` exponen las comprobaciones y límites. Las [pruebas públicas de esa revisión](https://github.com/idkmanager/firmar-ec/tree/6907d3d924f500e3379dd6c51506de318eb7ef81/packages/verifier/tests) permiten examinar los casos cubiertos. Su existencia no acredita todos los documentos, emisores o escenarios posibles.

Para una primera revisión práctica, sigue la [guía de uso del verificador](/verificar-firma-pdf/). Para reportar una discrepancia reproducible, consulta [los canales del proyecto](/acerca/).

## Cómo citar este recurso

Equipo IDK Manager. «Cómo interpretar la verificación de una firma PDF». firmar.ec, 18 de septiembre de 2026. https://firmar.ec/metodologia-verificacion/. Incluye la fecha de consulta si reutilizas esta lista en un procedimiento interno.
