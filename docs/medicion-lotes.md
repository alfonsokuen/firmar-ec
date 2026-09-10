# Medición anónima de lotes

Implementado y verificado localmente el 2026-09-10.

- `FirmarLote` emite un solo `lote` tras resolver `signBatchToZip` con al menos un PDF firmado. Incluye resultados parciales; un lote sin éxitos o un PIN incorrecto no cuentan.
- El beacon contiene únicamente `?type=lote`. No incluye documentos, cantidades, nombres, certificados ni identificadores.
- El backend acepta el evento y lo publica en `GET /api/stats/series`, en el campo `lote` de cada periodo, incluido cero para periodos vacíos. No se suma a `pdfsSigned` ni modifica la forma de `GET /api/stats`.
- El limitador valida el tipo antes de usar Redis y mantiene un cupo separado por tipo. Conserva capacidad y recarga existentes. Las direcciones compartidas del túnel todavía pueden causar infracontaje dentro de un mismo tipo; esto es una métrica orientativa de corridas, no un recuento exacto de PDFs.
- No requiere migración: las claves y tipos existentes son columnas de texto. El backend debe admitir `lote` antes de publicar la PWA nueva.

Verificación: 49 pruebas de stats-backend, 419 pruebas de PWA, comprobaciones de tipos de ambos y compilación de PWA. Playwright Chromium ejecutó firma real de dos PDFs hasta el ZIP: PIN incorrecto sin eventos, reintento válido con exactamente un `lote`, sin evento `sign` y sin cuerpo en el beacon. Biome no reportó errores en los TypeScript modificados; persisten avisos previos de consola. Svelte reportó cuatro advertencias en tres componentes ajenos al cambio.

No se ha desplegado ni enviado a remotos. La medición comienza al desplegar; no reconstruye lotes históricos.
