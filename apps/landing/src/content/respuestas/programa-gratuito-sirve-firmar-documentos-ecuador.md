---
title: "Programa gratuito para firmar documentos en Ecuador"
description: "Qué opciones gratuitas existen en Ecuador para firmar documentos con certificado electrónico: firmar.ec en el navegador y FirmaEC de escritorio, con sus diferencias reales."
question: "¿Qué programa gratuito sirve para firmar documentos en Ecuador?"
answer: "En Ecuador hay dos opciones gratuitas de verdad para firmar con certificado electrónico: firmar.ec, que funciona en el navegador sin instalar nada y es open source con licencia AGPL-3.0, y FirmaEC, la aplicación de escritorio oficial. Las dos producen firma electrónica válida en Ecuador; se diferencian en que una exige instalación y la otra no."
pubDate: "2026-09-07"
faq:
  - q: "¿Hay que registrarse o pagar para usar firmar.ec?"
    a: "No. No hay registro, cuenta ni pago: se abre la página, se carga el certificado .p12 y el PDF, y se firma. El código es abierto bajo licencia AGPL-3.0."
  - q: "¿El documento se sube a algún servidor para firmarlo?"
    a: "No. La firma se calcula dentro del navegador, en un Web Worker, con WebCrypto. Ni el PDF ni la llave privada salen del equipo para firmar; se puede comprobar en modo avión o mirando la pestaña Red del navegador."
  - q: "¿Sirve cualquier certificado ecuatoriano?"
    a: "Se admiten los certificados .p12 emitidos por entidades de certificación acreditadas por ARCOTEL. firmar.ec reconoce 16 de las 17 acreditadas, entre ellas BCE, Security Data, UANATACA, ANF AC, iCert-EC y ArgosData."
  - q: "¿Qué diferencia hay con las herramientas gratuitas internacionales?"
    a: "Muchas herramientas globales solo estampan una imagen de firma sobre el PDF, que no es una firma electrónica. Aquí se genera una firma PAdES conforme a ETSI EN 319 142, con el certificado del firmante."
relatedSlugs:
  - "/firmar-pdf-online-gratis-sin-instalar-programas/"
  - "/alternativa-firmaec/"
  - "/como-firmar-pdf/"
evidenceClaims: []
---

## La respuesta corta

En Ecuador hay dos opciones gratuitas de verdad para firmar con certificado electrónico: firmar.ec, que funciona en el navegador sin instalar nada y es open source con licencia AGPL-3.0, y FirmaEC, la aplicación de escritorio oficial. Las dos producen firma electrónica válida en Ecuador; se diferencian en que una exige instalación y la otra no.

## Qué significa "gratuito" aquí

Conviene separar dos cosas que suelen confundirse. El **programa** para firmar puede ser gratuito; el **certificado** de firma electrónica no lo es. El certificado `.p12` lo emite una entidad de certificación acreditada por ARCOTEL y tiene un costo y una vigencia propios. Lo gratuito es la herramienta que usa ese certificado para firmar.

También conviene distinguir firmar de *aparentar* que se firma. Varias herramientas internacionales gratuitas colocan una imagen de firma sobre el PDF: eso es un dibujo, no una firma electrónica, y no acredita quién firmó ni detecta si el documento se alteró después. Una firma electrónica real se apoya en el certificado del firmante y queda incrustada en el archivo con un formato normalizado.

## Las dos opciones gratuitas en Ecuador

**firmar.ec** funciona dentro del navegador, sin instalar programas ni controladores, y sin crear una cuenta. Se carga el certificado `.p12`, se carga el PDF y se descarga el documento firmado. La criptografía ocurre en el propio navegador mediante WebCrypto, en un Web Worker: ni el documento ni la llave privada se envían a un servidor para firmar. Es código abierto con licencia AGPL-3.0, de modo que cualquiera puede auditar cómo funciona. Reconoce los certificados de 16 de las 17 entidades acreditadas por ARCOTEL.

**FirmaEC** es la aplicación de escritorio oficial. Requiere instalación en el equipo y, según la versión y el sistema operativo, algo de configuración previa. Es la referencia habitual en trámites públicos y mucha gente ya la tiene instalada.

La elección práctica suele venir por el contexto: si hace falta firmar desde un equipo ajeno, desde un celular o sin permisos de instalación, la opción de navegador es la que funciona; si ya existe un flujo de trabajo montado sobre la aplicación de escritorio, no hay motivo para cambiarlo.

## Qué firma se obtiene

En firmar.ec el resultado es una firma **PAdES** conforme a la norma ETSI EN 319 142, el formato estándar de firma para documentos PDF. Puede incluir un sello de tiempo de una autoridad TSA según RFC 3161 e información de revocación OCSP/CRL incrustada, lo que permite comprobar la firma más adelante sin depender de servicios en línea.

La validez legal de la firma electrónica en Ecuador se apoya en la Ley de Comercio Electrónico (Ley 2002-67), y lo que la sostiene es el certificado emitido por una entidad acreditada, no la herramienta concreta que se use para aplicarla.

## Cómo comprobar que el documento no se subió

Es una duda razonable y se puede verificar sin fiarse de la palabra de nadie: basta desconectar la red —modo avión— y firmar igualmente, o abrir la pestaña Red del navegador y observar que no sale ninguna petición con el documento durante la firma. El código está publicado y puede revisarse. Sí usan red, y solo si se activan, el sello de tiempo y la información de revocación: en esos casos viaja el resumen criptográfico del documento, nunca el documento.
