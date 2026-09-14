# PWA changelog

## 0.27.0 — 2026-09-14

- El QR de los nuevos PDF firmados se puede pulsar para abrir el verificador. El receptor selecciona el PDF y la comprobación sigue siendo local. Incluye multifirma y páginas giradas.
- QA E2E de descarga y segunda firma, clic en el enlace renderizado por PDF.js y verificación del archivo, en escritorio y móvil.

## 0.26.3 — 2026-09-11

- Cuenta una operación por lote completado sin contar un PIN incorrecto ni cada PDF como firma individual.
- QA E2E local y postdespliegue en escritorio y móvil: descarga PDF y ZIP, verificación criptográfica independiente y recuperación de PIN incorrecto. Las pruebas live interceptan estadísticas para evitar contaminar métricas.
