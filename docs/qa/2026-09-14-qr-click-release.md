# QA previo a despliegue — PWA 0.27.0 / signer 0.12.0

Fecha: 2026-09-14. Alfonso autorizó QA E2E y despliegue.

- Base integrada: gitea/main 69f1c898f322 (PWA 0.26.3 en producción, 2/2 réplicas).
- Rama de respaldo del cambio original: backup/qr-click-before-integration-20260914 (7778a5f).
- Respaldo privado de las especificaciones PWA y landing guardado en el manager antes del despliegue; imagen anterior comprobada disponible. No hay cambios de datos ni migraciones.
- Typecheck del signer correcto. Biome correcto en código nuevo, pruebas y manifests. El diff no introduce endpoints: el enlace reutiliza buildVerifyQrUrl, fuente canónica del QR.
- Suite del signer: 48 archivos / 566 pruebas correctas.
- Gate PWA + packages + landing: 155 archivos correctos, 1 omitido; 1.415 pruebas correctas, 8 omitidas. Se mantiene la exclusión preexistente de ltv-validation/tests/property.test.ts del gate oficial.
- Build PWA correcto: guardas de versión y contenido correctas, versión servida por el artefacto 0.27.0.
- E2E contra el build: 8/8 en Chromium y móvil, sin reintentos. Firma individual, PIN incorrecto, firma de lote de 2 PDF y ZIP, y nuevo escenario QR con segunda firma.
- El nuevo escenario firma en la UI real, descarga, comprueba CMS/digest/ByteRange con el helper independiente, conserva bytes previos al añadir segunda firma, renderiza el PDF descargado con PDF.js, pulsa su anotación Link real y llega al verificador; al seleccionar el archivo aparecen ambas firmas. La advertencia de confianza es esperada porque se usa el certificado sintético de fixtures.
- El harness de PDF.js y la redirección al origen local existen únicamente en la prueba. El E2E postdespliegue usa el enlace de producción sin esa redirección. Las estadísticas se interceptan para no contaminar métricas reales.
- Fallos de la prueba corregidos con evidencia: reiniciar con «Firmar otro PDF», seleccionar el enlace por URL (el visor no conserva el orden de anotaciones) y aceptar los textos ES/EN según el idioma del navegador.

Comandos:

```
pnpm --filter @firma-ec/signer typecheck
pnpm --filter @firma-ec/signer test
pnpm exec vitest run apps/pwa packages apps/landing --exclude "**/ltv-validation/tests/property.test.ts"
pnpm --filter @firma-ec/pwa build
PWA_E2E_BASE_URL=http://127.0.0.1:5187 pnpm --filter @firma-ec/pwa test:e2e:live-signing
```

Postdespliegue: repetir test:e2e:live-signing contra app.firmar.ec, comprobar versión 0.27.0 y convergencia al SHA publicado. Si hay fallo funcional atribuible a esta release, volver a la imagen inmutable previa comprobada. Los PDF ya emitidos no se modifican.

## Verificación pública y ajuste del gate Linux

- Primer despliegue: b5bb38a3296b, Gitea run 2927 correcto, 2/2 réplicas. E2E público 8/8, versión 0.27.0 comprobada en sesión nueva, home 200 y 404 de assets con no-store.
- El gate Linux (run 2928) completó 1.411 pruebas y agotó el límite por defecto de 5s en las cuatro pruebas QR de multifirma (~7.8s en el contenedor con 4 CPU). Se asigna un presupuesto de 20s solo a esas pruebas de integración; sin reintentos, exclusiones ni cambios en las aserciones. La aplicación publicada no cambia.
