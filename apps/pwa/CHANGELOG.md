# PWA changelog

## 0.28.1 — 2026-09-24

- Motor de verificación 0.10.1 (seguridad), tras una revisión independiente de lo desplegado en 0.28.0: una revocación listada en una CRL con alcance parcial o delta vuelve a contar (incluidas las ARL de CA, que se descartaban); la evidencia de «no revocado» emitida después de caducar el certificado ya no cuenta; material de revocación omitido obliga a consultar el OCSP en vivo; un certificado de sellado de tiempo debe tener `timeStamping` como único uso extendido y crítico.

## 0.28.0 — 2026-09-24

- Motor de verificación 0.10.0 (seguridad). El verificador comprobaba la cadena del último certificado de la lista y no la del firmante: un certificado forjado bajo el nombre de una CA acreditada podía salir «Firma válida», y en documentos con varias firmas una firma legítima podía salir «Firma inválida». Afectaba a «Verificar firma» y a «Validar certificado». Detalle técnico en el CHANGELOG raíz.
- Los sellos de tiempo se autentican de verdad (no se puede reescribir su fecha), la consulta de revocación (OCSP) se autentica, y una revocación solo invalida una firma si ocurrió antes de la hora probada.
- Se reconocen los sellos de tiempo de las ECI acreditadas por ARCOTEL (Security Data, BCE, UANATACA Ecuador, MINTEL TSU02…) y las firmas de APPFIRMAS 2025.
- Nuevos avisos: «Fecha de firma no demostrada» (certificado caducado y sin sello válido), revocación posterior a la firma y revocación no comprobada.

## 0.27.0 — 2026-09-14

- El QR de los nuevos PDF firmados se puede pulsar para abrir el verificador. El receptor selecciona el PDF y la comprobación sigue siendo local. Incluye multifirma y páginas giradas.
- QA E2E de descarga y segunda firma, clic en el enlace renderizado por PDF.js y verificación del archivo, en escritorio y móvil.

## 0.26.3 — 2026-09-11

- Cuenta una operación por lote completado sin contar un PIN incorrecto ni cada PDF como firma individual.
- QA E2E local y postdespliegue en escritorio y móvil: descarga PDF y ZIP, verificación criptográfica independiente y recuperación de PIN incorrecto. Las pruebas live interceptan estadísticas para evitar contaminar métricas.
