# PWA changelog

## 0.26.3 — 2026-09-11

- Cuenta una operación por lote completado sin contar un PIN incorrecto ni cada PDF como firma individual.
- QA E2E local y postdespliegue en escritorio y móvil: descarga PDF y ZIP, verificación criptográfica independiente y recuperación de PIN incorrecto. Las pruebas live interceptan estadísticas para evitar contaminar métricas.
