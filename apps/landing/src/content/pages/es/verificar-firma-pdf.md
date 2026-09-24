---
title: "Cómo verificar la firma de un PDF en Ecuador"
description: "Verifica si un PDF firmado es válido: integridad del documento, certificado de una ECI de ARCOTEL y estado de revocación. En el navegador, sin instalar nada."
lang: es
dateModified: "2026-09-18"
datePublished: "2026-05-25"
h1: "Cómo verificar la firma electrónica de un PDF"
breadcrumbs:
  - { name: "Verificar firma de un PDF", url: "https://firmar.ec/verificar-firma-pdf/" }
related:
  - { title: "¿Qué es PAdES?", href: "/que-es-firma-pades/" }
  - { title: "Firma electrónica en Ecuador", href: "/firma-electronica-ecuador/" }
  - { title: "Cómo firmar con certificado BCE", href: "/como-firmar-con-certificado-bce/" }
---

> **¿Cómo verificas que un PDF firmado es válido en Ecuador?** Sube el PDF al verificador de [app.firmar.ec/verificar](https://app.firmar.ec/#/verificar): comprueba en tu navegador tres cosas — que el **documento no fue alterado** después de firmarse, que el **certificado** proviene de una Entidad de Certificación de Información (ECI) acreditada por ARCOTEL, y su **estado de revocación** (OCSP/CRL). Es gratis, no instalas nada y el archivo nunca se sube a un servidor.

## ¿Qué significa que una firma sea "válida"?

Una firma electrónica sobre un PDF es válida en Ecuador cuando se cumplen **tres condiciones** a la vez:

1. **Integridad** — el contenido del PDF no cambió ni un byte después de firmarse. Si alguien lo edita tras la firma, la verificación falla.
2. **Certificado confiable** — el certificado del firmante fue emitido por una **ECI acreditada por ARCOTEL**. La firma con un certificado válido tiene la misma validez legal que una firma manuscrita (Ley de Comercio Electrónico, LCE 2002-67).
3. **Vigencia / no revocación** — el certificado estaba **vigente y no revocado** en el momento de firmar. Esto se comprueba contra el servicio de la AC (OCSP en tiempo real, o las listas CRL).

## Cómo verificar, paso a paso

1. Abre el verificador en [app.firmar.ec/verificar](https://app.firmar.ec/#/verificar).
2. Arrastra o selecciona el **PDF firmado** que quieres comprobar.
3. Lee el resultado: **firmante, AC emisora, fecha de la firma, integridad** y estado del certificado.
4. *(Opcional)* Si el documento trae un **sello visible con código QR**, escanéalo: el QR enlaza al verificador con el hash del documento (`verificar?h=<hash>`) para comprobarlo directamente.

Todo el proceso ocurre **en tu navegador**: el PDF no viaja a ningún servidor.

## Qué te dice el verificador

- Quién firmó (nombre del titular del certificado) y qué **AC ecuatoriana** lo emitió.
- Si la **integridad** del documento está intacta.
- El **perfil PAdES** de la firma (B-B, B-T, B-LT o B-LTA) y, si lleva **sello de tiempo** (TSA RFC 3161), la fecha certificada.
- El estado de **revocación** del certificado (OCSP/CRL).

## ¿Y si no uso firmar.ec?

También puedes verificar una firma PAdES en **Adobe Acrobat Reader** (panel de firmas) o en el **validador oficial del MINTEL** ([minka.gob.ec](https://minka.gob.ec)). Un PDF firmado en firmar.ec se valida correctamente en cualquiera de ellos, y viceversa: todos producen y leen el mismo perfil técnico **PAdES Baseline** (ETSI EN 319 142).

## Preguntas frecuentes

**¿Necesito instalar algo para verificar?** No. El verificador de firmar.ec funciona en cualquier navegador moderno, también en el celular.

**¿La verificación funciona sin internet?** La comprobación de integridad y de la cadena del certificado sí; la consulta de revocación en tiempo real (OCSP) requiere conexión.

**Recibí un PDF y dice "firma inválida", ¿qué hago?** Suele significar que el documento se editó después de firmarse, o que el certificado estaba caducado/revocado al firmar. Pide al emisor que vuelva a firmar el documento final.

## Interpretar los resultados

Consulta la [metodología de verificación de firmas PDF](/metodologia-verificacion/): integridad, confianza, revocación y tiempo son comprobaciones distintas. Incluye una lista para documentar la revisión y sus límites.
