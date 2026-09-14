# Medición anónima de lotes

Implementado y verificado localmente el 2026-09-10.

- `FirmarLote` emite un solo `lote` tras resolver `signBatchToZip` con al menos un PDF firmado. Incluye resultados parciales; un lote sin éxitos o un PIN incorrecto no cuentan.
- El beacon contiene únicamente `?type=lote`. No incluye documentos, cantidades, nombres, certificados ni identificadores.
- El backend acepta el evento y lo publica en `GET /api/stats/series`, en el campo `lote` de cada periodo, incluido cero para periodos vacíos. No se suma a `pdfsSigned` ni modifica la forma de `GET /api/stats`.
- El limitador valida el tipo antes de usar Redis y mantiene un cupo separado por tipo. Conserva capacidad y recarga existentes. Las direcciones compartidas del túnel todavía pueden causar infracontaje dentro de un mismo tipo; esto es una métrica orientativa de corridas, no un recuento exacto de PDFs.
- No requiere migración: las claves y tipos existentes son columnas de texto. El backend debe admitir `lote` antes de publicar la PWA nueva.

Verificación: 49 pruebas de stats-backend, 419 pruebas de PWA, comprobaciones de tipos de ambos y compilación de PWA. Playwright Chromium ejecutó firma real de dos PDFs hasta el ZIP: PIN incorrecto sin eventos, reintento válido con exactamente un `lote`, sin evento `sign` y sin cuerpo en el beacon. Biome no reportó errores en los TypeScript modificados; persisten avisos previos de consola. Svelte reportó cuatro advertencias en tres componentes ajenos al cambio.

No se ha desplegado ni enviado a remotos. La medición comienza al desplegar; no reconstruye lotes históricos.

## Aislamiento HTTP — stats-backend 0.2.1 (2026-09-10)

Además del cubo Redis, existía un límite HTTP de 100 peticiones/minuto que compartían todos los eventos y lecturas. Las pruebas anteriores lo desactivaban. Se reprodujo con Fastify y su plugin activos: tras 100 peticiones `lote`, una firma nueva recibía 429 aunque su cubo Redis estuviera disponible.

La ruta de eventos mantiene 100 peticiones/minuto por IP efectiva de Fastify y tipo reconocido (`sign`, `verify`, `cert`, `install`, `lote`). Todos los tipos inválidos comparten un sexto cupo; no se interpolan nombres arbitrarios en claves. Consulta y JSON comparten parser y precedencia: un `type` de consulta inválido no se rescata con un cuerpo válido. El hook `preValidation` permite leer el JSON antes de seleccionar el cupo. Las lecturas conservan el cupo HTTP general de 100/minuto.

Los siete cupos suman como máximo 700 peticiones admitidas a esos hooks por minuto/IP/proceso. Esto es una suma de límites independientes, **no** un limitador agregado atómico de 700: las respuestas 429 no consumen otros cupos; JSON malformado se rechaza antes del hook; las rutas inexistentes siguen respondiendo 404. El límite de cuerpo de 64 KB permanece. La protección HTTP usa memoria local y se multiplica por el número de réplicas; los cubos Redis de 20 eventos/hora/tipo siguen compartidos entre réplicas. Una indisponibilidad de Redis conserva el comportamiento previo de aceptar eventos con warning, protegido por el límite HTTP.

No cambia `trustProxy: true`, ni se acepta `CF-Connecting-IP` como nueva identidad. Sigue pendiente verificar la cadena real del proxy antes de prometer un cupo por visitante: visitantes que compartan IP efectiva también comparten cupos. No corrige el infracontaje existente dentro de un tipo ni reconstruye eventos descartados.

Verificación local: negativo inicial (3 fallos y 1 aprobado); después 6 pruebas HTTP aprobadas y suite completa 55/55, typecheck, build y Biome. Incluye saturación lote→sign/verify/lecturas, conservación del máximo HTTP y Redis, JSON→query, inválidos sin claves Redis, consulta inválida con cuerpo válido, parámetros duplicados y variantes de ruta rechazadas. No se generaron eventos artificiales en producción.
