<script lang="ts">
import { onDestroy } from 'svelte';
import { push } from 'svelte-spa-router';
import {
  type ManualBoxPosition,
  needsOverlapConfirmation,
  overlapsExistingSignature,
  toManualPlacement,
} from '../lib/batch/manualPlacement';
import {
  EFFECTIVE_MAX_FILES,
  type PreflightItem,
  type RejectedFile,
  acceptFiles,
  preflightBatch,
  splitPreflightWork,
  toBatchInput,
} from '../lib/batch/preflight';
import {
  buildPropagationHint,
  isPropagationDowngrade,
  mergePropagationResult,
  propagationCandidates,
} from '../lib/batch/propagation';
/**
 * FirmarLote.svelte — firma por lotes: elegir varios PDFs, ver dónde caerá la
 * estampa en cada uno, firmarlos con una sola contraseña y bajar un ZIP.
 *
 * El orden de los pasos es la decisión de diseño que importa: la revisión de
 * colocación va ANTES del PIN. El motor decide la colocación mientras firma y
 * aparta lo que no admite un rect defendible; si eso se descubre al final, la
 * persona ya escribió su contraseña y ya esperó 20 minutos para enterarse de que
 * 30 documentos no salieron. Aquí lo sabe antes de decidir nada.
 *
 * Privacidad (invariante del proyecto): ni el nombre de un documento ni el PIN
 * ni la cédula del firmante salen de esta pantalla. Solo se cuenta el tipo de
 * evento anónimo al completar un lote con alguna firma. No hay logs con datos
 * del usuario, y el PIN se borra en cuanto deja de hacer falta.
 */
import type { SignatureScan } from '../lib/batch/signatureScan.ts';
import {
  BatchZipCapacityError,
  type BatchZipResult,
  assertBatchFitsZip,
  signBatchToZip,
  stripControlChars,
  zipEntryNameFor,
} from '../lib/export/batchZip';
import { type UIKey, getLang, t, tp } from '../lib/i18n.svelte.ts';
import { getSettings } from '../lib/settings.svelte.ts';
import { pingUsage } from '../lib/statsBeacon';
import { holdReload, releaseReload } from '../lib/swUpdate.svelte.ts';
import { type BatchQueueItem, MAX_BATCH_FILE_SIZE_BYTES } from '../lib/workers/sign-queue';
import BoxPlacer from '../ui/firma/BoxPlacer.svelte';
import DropP12 from '../ui/firma/DropP12.svelte';
import PdfPreview from '../ui/firma/PdfPreview.svelte';
import PinInput from '../ui/firma/PinInput.svelte';
import WizardProgress from '../ui/firma/WizardProgress.svelte';
import WizardShell from '../ui/firma/WizardShell.svelte';
import {
  DEFAULT_SIG_BOX_H,
  DEFAULT_SIG_BOX_W,
  type ExistingSigRect,
  type PageDim,
  computeSmartPlacement,
  placeAtBottomLastPage,
} from '../ui/firma/smartPlacement.ts';
import DropLote from '../ui/lote/DropLote.svelte';
import LoteList, { type LoteRow } from '../ui/lote/LoteList.svelte';

/**
 * Alias local: `ManualBoxPosition` (`../lib/batch/manualPlacement`) es
 * estructuralmente igual a `BoxPosition` de `BoxPlacer.svelte` (page 1-based,
 * PDF pt) — no se importa ESE tipo directamente porque un `<script>` de
 * componente Svelte no expone sus tipos a un import normal; `Firmar.svelte`
 * resuelve lo mismo con su propio `interface BoxPos` local (ver ese archivo).
 */
type PlacerBoxPosition = ManualBoxPosition;

const STEPS: { id: string; labelKey: UIKey }[] = [
  { id: 'select', labelKey: 'lote.step.select' },
  { id: 'review', labelKey: 'lote.step.review' },
  { id: 'sign', labelKey: 'lote.step.sign' },
  { id: 'done', labelKey: 'lote.step.done' },
];

const lang = $derived(getLang());
$effect(() => {
  void lang;
});

// ---------- Estado ----------
let step = $state(1);

let files = $state<File[]>([]);
let rejected = $state<RejectedFile[]>([]);
let capacityError = $state<string | null>(null);

let preflight = $state<PreflightItem[]>([]);
let preflightRunning = $state(false);
/** Identifica la revisión en curso: solo ella puede escribir el estado. */
let preflightRun = 0;
let preflightAbort: AbortController | null = null;
/**
 * Rastro de PROCEDENCIA para la reconciliación final de `goToReview`: qué
 * archivos escribió una acción de la persona (`commitPlacement`) o una
 * propagación (`propagateFrom`) DESDE que arrancó la corrida de preflight en
 * curso. Reinicia justo antes del `await` de `preflightBatch`.
 *
 * QA post-merge 2026-08-03 (silent-failure-hunter, ronda 2): reemplaza el
 * marcador `manual`/`propagated` que usaba el primer fix del bug P0 — ese
 * marcador es de PRESENTACIÓN, no de procedencia. Una propagación puede
 * resolver un documento a `ready` SIN poner `propagated` (fuente
 * `empty-field`, o sin geometría para la página resuelta — ver
 * `classifyPropagation` en `preflight-core.ts`), y ese resultado se colaba
 * por la misma rendija que el P0 original: la reconstrucción lo devolvía a
 * la foto vieja (`needs_review`) porque no llevaba ninguna marca que lo
 * distinguiera. Rastrear el ARCHIVO escrito, no una propiedad de su
 * contenido, cierra la rendija para cualquier estado futuro de propagación.
 */
let writtenSincePreflightSnapshot = new Set<File>();
/** Archivos que se están re-analizando por una propagación en curso — se
 *  pintan `tone:'busy'` en reviewRows mientras dura (F2c). */
let propagatingFiles = $state<Set<File>>(new Set());
/**
 * Ciclo de vida PROPIO de `propagateFrom`, separado a propósito de
 * `preflightRun`/`preflightAbort` (los de `goToReview`). Antes del fix del
 * bug P0, `propagateFrom` reusaba el contador/abort de `goToReview`: si una
 * colocación manual llegaba MIENTRAS el análisis inicial del lote seguía
 * corriendo, `propagateFrom` abortaba esa corrida inicial a media marcha —
 * `goToReview` veía `run !== preflightRun` al volver de `preflightBatch` y
 * hacía `return` sin reconstruir la lista final, y los documentos que
 * todavía no se habían analizado desaparecían del lote sin aviso. Con
 * contadores separados, una propagación nunca puede cortar el análisis
 * inicial (ni viceversa): cada uno solo invalida corridas de SU MISMA especie.
 */
let propagationRun = 0;
let propagationAbort: AbortController | null = null;
/** `true` mientras cualquier propagación está en vuelo — bloquea "Continuar"
 *  igual que `preflightRunning`, pero es la variable de `propagateFrom`, no
 *  la de `goToReview` (ver comentario de `propagationRun` arriba). */
const isPropagating = $derived(propagatingFiles.size > 0);
/** Aviso descartable cuando una propagación falla por algo que no es el
 *  rechazo normal de hint (p. ej. el Worker no se pudo levantar) — sin esto,
 *  el fallo se pierde como una unhandled rejection invisible. */
let propagationError = $state<string | null>(null);

// ---------- Paso 2 (sub-vista): colocador manual de UN documento ----------
/** El `PreflightItem` que se está colocando a mano, o `null` fuera de la sub-vista. */
let placing = $state<PreflightItem | null>(null);
/** Bytes del documento en colocación — SOLO el que se está colocando, nunca
 *  se cachean los bytes de los 50 documentos del lote en memoria. */
let placingBytes = $state<Uint8Array | null>(null);
let placingLoadError = $state<string | null>(null);
let placingBoxPos = $state<PlacerBoxPosition | null>(null);
let placingPageInfo = $state<{ pdfWidth: number; pdfHeight: number } | null>(null);
let placingCurrentPage = $state<number>(0);
let placingAutoPlaceDefault = $state<boolean>(true);
/** Widgets de firma existentes EN ESE documento (escaneados por PdfPreview),
 *  usados para el aviso de solape al confirmar. */
let placingWidgets = $state<ExistingSigRect[]>([]);
/** El rect confirmado se solapa con una firma previa: se exige una segunda
 *  confirmación explícita antes de aceptar (ver `requestConfirm`). */
let placingOverlapPending = $state(false);
/**
 * El barrido de firmas previas de ESTE documento no pudo mirarlo entero. Se
 * conserva para `requestConfirm`: mientras sea `true`, "no solapa" no es una
 * afirmacion que podamos hacer. Ver `needsOverlapConfirmation`.
 */
let placingScanIncomplete = $state(false);

let p12 = $state<ArrayBuffer | null>(null);
let p12Name = $state('');
let pin = $state('');
let p12Error = $state<string | null>(null);
let pinError = $state<string | null>(null);

let signing = $state(false);
let cancelling = $state(false);
let signAbort: AbortController | null = null;
/** Estado vivo por documento durante la firma, indexado por el id del motor. */
let liveItems = $state<BatchQueueItem[]>([]);

let result = $state<BatchZipResult | null>(null);
let zipUrl = $state<string | null>(null);
/**
 * QA post-merge 2026-08-03 (silent-failure-hunter): cuando la escritura al
 * ZIP falla para un documento YA FIRMADO (`delivery_error`), `sign-queue.ts`
 * conserva a propósito sus bytes como "lifeline" — comentario textual: "keep
 * the signed bytes so the caller can retry the write WITHOUT signing again
 * (a signature costs a PKCS#7 + TSA + OCSP round trip)". Antes de este fix
 * esos bytes llegaban intactos hasta aquí y se tiraban: la fila solo decía
 * "firmado, pero no se pudo guardar en el ZIP", sin ninguna forma de bajar
 * ese PDF. Un Blob URL por documento recuperable, poblado junto a `zipUrl`.
 */
let recoveryUrls = $state<Map<string, string>>(new Map());
let downloaded = $state(false);
let fatalError = $state<string | null>(null);
/** Error de `goToReview` propio del paso 2 — `fatalError` vive dentro de la
 *  rama del paso 3, así que un rechazo en el paso 2 nunca lo pintaba. */
let reviewError = $state<string | null>(null);

// ---------- Derivados ----------
const maxSizeLabel = formatBytes(MAX_BATCH_FILE_SIZE_BYTES);

/** Documentos que el pre-flight dio por firmables — los únicos que van al motor. */
const signable = $derived(preflight.filter((i) => i.status === 'ready'));
const excludedByPreflight = $derived(preflight.filter((i) => i.status !== 'ready'));

const signedCount = $derived(liveItems.filter((i) => i.status === 'done').length);

/** Copy bytes into a fresh ArrayBuffer so TS BlobPart accepts them
 *  (Uint8Array<ArrayBufferLike> may include SharedArrayBuffer) — mismo
 *  patrón que `DownloadResult.svelte`/`Inbox.svelte`. */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u8.byteLength);
  new Uint8Array(out).set(u8);
  return out;
}

function formatBytes(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${Math.round(mb)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/** Traduce el motivo del motor; si es uno que no conocemos, lo muestra tal cual
 *  en vez de tragárselo — un motivo sin traducir informa más que ninguno. */
function reasonLabel(reason: string | undefined): string {
  if (!reason) return '';
  const key = `lote.review.reason.${reason}` as UIKey;
  const translated = t(key);
  return translated === key ? reason : translated;
}

/** Misma regla que reasonLabel: una fuente sin traducir se muestra tal cual
 *  en vez de desaparecer -- un mudo aquí es peor que un código feo. */
function sourceLabel(source: string | undefined): string {
  if (!source) return '';
  const key = `lote.review.source.${source}` as UIKey;
  const translated = t(key);
  return translated === key ? source : translated;
}

// ---------- Paso 1: selección ----------
function addFiles(incoming: File[]): void {
  capacityError = null;
  const { accepted, rejected: bad } = acceptFiles(incoming, files.length);
  if (accepted.length > 0) files = [...files, ...accepted];
  if (bad.length > 0) rejected = [...rejected, ...bad];
}

function removeFile(id: string): void {
  const index = Number(id.replace('sel-', ''));
  files = files.filter((_, i) => i !== index);
  capacityError = null;
}

function clearFiles(): void {
  files = [];
  rejected = [];
  capacityError = null;
}

const selectRows = $derived<LoteRow[]>(
  files.map((file, i) => ({
    id: `sel-${i}`,
    name: stripControlChars(file.name),
    meta: formatBytes(file.size),
    tone: 'neutral' as const,
    removable: true,
  })),
);

// ---------- Paso 2: revisión de colocación ----------
async function goToReview(): Promise<void> {
  // El lote entero tiene que caber en un ZIP, y eso se sabe ANTES de firmar
  // nada: descubrirlo después significaría 50 documentos firmados que no se
  // pueden entregar.
  try {
    assertBatchFitsZip(files);
  } catch (e) {
    if (e instanceof BatchZipCapacityError) {
      capacityError = t('lote.reject.zip_too_large');
      return;
    }
    throw e;
  }

  // Cada entrada al paso 2 es una corrida con nombre propio. Sin esto, volver
  // atrás y entrar otra vez dejaba dos revisiones escribiendo sobre el mismo
  // estado: filas duplicadas, "Continuar" habilitado con la lista a medias, y
  // el mismo documento llegando dos veces al motor.
  const run = ++preflightRun;
  preflightAbort?.abort();

  // Cualquier propagación de la revisión ANTERIOR es basura frente a este
  // análisis nuevo: invalidarla (su propio ciclo, nunca el de `goToReview` —
  // ver `propagationRun`) y limpiar `propagatingFiles` de inmediato, en vez
  // de esperar a que el `finally` de esa propagación lo haga (no lo hará: su
  // guarda es `run === preflightRun`, que ya no coincidirá una vez que este
  // análisis reconstruya `preflight` desde cero).
  propagationRun++;
  propagationAbort?.abort();
  propagatingFiles = new Set();
  propagationError = null;

  // Preflight INCREMENTAL: un documento que ya se analizó en una entrada
  // anterior a este paso no se vuelve a analizar. Solo lo nuevo (`pending`)
  // pasa por el worker; lo ya resuelto (`kept`) se conserva tal cual —
  // incluido cualquier `placement` que traiga calculado.
  const { kept, pending } = splitPreflightWork(files, preflight);
  writtenSincePreflightSnapshot = new Set();

  step = 2;
  preflight = kept;
  preflightRunning = true;
  reviewError = null;
  preflightAbort = new AbortController();

  // QA post-merge 2026-08-03 (silent-failure-hunter, ronda 2): sin
  // try/finally, un rechazo de `preflightBatch` (el Worker puede lanzar
  // síncronamente por CSP/SecurityError, o `openPreflightSession` puede
  // rechazar) dejaba `preflightRunning` clavado en `true` para siempre —
  // spinner eterno, "Continuar" deshabilitado sin salida salvo recargar — y
  // el `catch` de `next()` fijaba `fatalError`, que vive dentro de la rama
  // del paso 3 y por lo tanto nunca se pintaba estando en el paso 2.
  try {
    const report =
      pending.length > 0
        ? await preflightBatch(pending, {
            runId: `r${run}`,
            signal: preflightAbort.signal,
            onItem: (item) => {
              if (run !== preflightRun || !files.includes(item.file)) return;
              preflight = [...preflight, item];
            },
          })
        : { items: [] };

    if (run !== preflightRun) return;
    // El resultado final NO se vuelca tal cual: un documento que la persona quitó
    // mientras la revisión corría no debe reaparecer, y el orden final tiene que
    // reflejar la selección (`files`) — no el orden en que `kept` y `pending`
    // terminaron de resolverse por separado.
    //
    // QA post-merge 2026-08-03: `kept`/`report.items` son fotos tomadas ANTES
    // de este await. `writtenSincePreflightSnapshot` (ver su declaración) es
    // la procedencia REAL de lo escrito DURANTE el await — se prefiere sobre
    // las fotos para esos archivos, y solo para esos; todo lo demás sigue
    // viniendo de las fotos como antes.
    const live = new Map(preflight.map((item) => [item.file, item]));
    const byFile = new Map([...kept, ...report.items].map((item) => [item.file, item]));
    preflight = files
      .map((file) => {
        if (writtenSincePreflightSnapshot.has(file)) return live.get(file) ?? byFile.get(file);
        return byFile.get(file);
      })
      .filter((item): item is PreflightItem => item !== undefined);
  } catch (e) {
    if (run !== preflightRun) return;
    console.error(`[lote] goToReview failed: ${(e as Error)?.name ?? 'unknown'}`);
    reviewError = t('lote.error.generic');
  } finally {
    if (run === preflightRun) preflightRunning = false;
  }
}

/**
 * Re-analiza los `needs_review` con la MISMA firma de formato que `sourceItem`,
 * pasándoles su posición confirmada como hint.
 *
 * Corre en SU PROPIO ciclo de vida (`propagationRun`/`propagationAbort`),
 * separado del de `goToReview` (`preflightRun`/`preflightAbort`) — ver el
 * comentario junto a la declaración de `propagationRun` para el bug P0 que
 * compartir esos contadores producía.
 */
async function propagateFrom(sourceItem: PreflightItem): Promise<void> {
  const hint = buildPropagationHint(sourceItem);
  if (!hint) return;
  const candidates = propagationCandidates(preflight, sourceItem);
  if (candidates.length === 0) return;

  const run = ++propagationRun;
  propagationAbort?.abort();
  const candidateFiles = candidates.map((c) => c.file);
  const previousByFile = new Map(candidates.map((c) => [c.file, c]));
  propagatingFiles = new Set(candidateFiles);
  propagationError = null;
  propagationAbort = new AbortController();

  // `hintByIndex` es por POSICIÓN dentro de la lista que se le pasa a
  // `preflightBatch` (aquí, `candidateFiles`) — no del lote completo. Como
  // el mismo hint aplica a TODOS los candidatos (misma firma de geometría),
  // el mapa cubre cada índice de esa sublista.
  const hintByIndex = new Map(candidateFiles.map((_, i) => [i, hint]));

  // QA post-merge 2026-08-03 (silent-failure-hunter): la guarda anti-downgrade
  // de `mergePropagationResult` hace lo correcto con los DATOS (nunca pisa un
  // documento ya conocido-legible con un `unreadable` transitorio), pero
  // convertía un fallo operativo real (el worker de análisis crasheó a mitad
  // de la propagación) en un no-evento: las filas volvían a "Necesita
  // revisión" sin ningún aviso, como si la propagación nunca se hubiera
  // intentado. Contar cuántas veces la guarda tuvo que intervenir y avisar.
  let downgradesPrevented = 0;
  const trackMerge = (previous: PreflightItem, next: PreflightItem): PreflightItem => {
    if (isPropagationDowngrade(previous, next)) downgradesPrevented++;
    // Ver `writtenSincePreflightSnapshot`: cualquier escritura de propagación
    // sobre `preflight` cuenta como "procedencia posterior a la foto",
    // gane o pierda la guarda anti-downgrade.
    writtenSincePreflightSnapshot.add(next.file);
    return mergePropagationResult(previous, next);
  };

  try {
    const report = await preflightBatch(candidateFiles, {
      runId: `prop${run}`,
      signal: propagationAbort.signal,
      hintByIndex,
      onItem: (item) => {
        if (run !== propagationRun) return;
        preflight = preflight.map((i) => {
          if (i.file !== item.file) return i;
          const previous = previousByFile.get(i.file) ?? i;
          return trackMerge(previous, item);
        });
      },
    });
    if (run !== propagationRun) return;
    // `onItem` ya escribió cada resultado a medida que llegaba; esto cubre el
    // caso raro de que `report.items` traiga algo que `onItem` no haya
    // cubierto (misma cautela que `goToReview`), con la misma protección
    // anti-downgrade.
    const byFile = new Map(report.items.map((item) => [item.file, item]));
    preflight = preflight.map((i) => {
      const next = byFile.get(i.file);
      if (next === undefined) return i;
      const previous = previousByFile.get(i.file) ?? i;
      return trackMerge(previous, next);
    });
    if (downgradesPrevented > 0) {
      propagationError = t('lote.review.propagation_failed');
    }
  } finally {
    if (run === propagationRun) {
      propagatingFiles = new Set();
    }
  }
}

function removeFromReview(id: string): void {
  const item = preflight.find((i) => i.id === id);
  preflight = preflight.filter((i) => i.id !== id);
  if (item) files = files.filter((f) => f !== item.file);
}

const reviewRows = $derived<LoteRow[]>(
  preflight.map((item) => {
    const isFilePropagating = propagatingFiles.has(item.file);
    const baseRow = {
      id: item.id,
      name: stripControlChars(item.file.name),
      meta:
        item.pageCount > 0
          ? // `item.page` viene en base 0 desde el motor; la persona cuenta desde 1.
            tp('lote.review.page_of', { p: item.page + 1, total: item.pageCount })
          : formatBytes(item.file.size),
      removable: true,
    };

    // Todavía re-analizándose por una propagación en curso: sin importar el
    // status previo (`ready` o `needs_review`), no hay nada que ajustar aún.
    if (isFilePropagating) {
      return {
        ...baseRow,
        statusLabel:
          item.status === 'ready' ? t('lote.review.ready') : t('lote.review.needs_review'),
        detail: t('lote.review.propagating'),
        tone: 'busy' as const,
        action: undefined,
      };
    }

    if (item.status === 'ready') {
      const adjustAction = { label: t('lote.review.adjust'), onClick: () => void openPlacer(item) };
      // `hint_rejected` documenta un fallo real de la propagación (el hint que
      // llegó no pasó la validación de esta capa): defensa en profundidad
      // barata — hoy es inalcanzable en la práctica porque
      // `buildPropagationHint` ya valida antes de construir el hint, pero un
      // `else` mudo para un estado que existe para reportar un fallo sería una
      // guarda muerta.
      if (item.propagated === 'hint_rejected') {
        return {
          ...baseRow,
          statusLabel: t('lote.review.ready'),
          detail: t('lote.review.propagation_failed_detail'),
          tone: 'ok' as const,
          action: adjustAction,
        };
      }
      return {
        ...baseRow,
        statusLabel: t('lote.review.ready'),
        detail:
          item.propagated === 'exact'
            ? t('lote.review.propagated_exact')
            : item.propagated === 'moved'
              ? t('lote.review.propagated_moved')
              : item.manual
                ? t('lote.review.manual_placed')
                : sourceLabel(item.source),
        tone: 'ok' as const,
        action:
          item.propagated === 'exact' || item.propagated === 'moved' ? adjustAction : undefined,
      };
    }

    if (item.status === 'needs_review') {
      return {
        ...baseRow,
        statusLabel: t('lote.review.needs_review'),
        detail: reasonLabel(item.reason),
        tone: 'warn' as const,
        action: { label: t('lote.review.sign_one_manually'), onClick: () => void openPlacer(item) },
      };
    }

    return {
      ...baseRow,
      statusLabel: t('lote.review.unreadable'),
      detail: reasonLabel(item.reason),
      tone: 'err' as const,
      action: undefined,
    };
  }),
);

// ---------- Paso 2 (sub-vista): colocador manual ----------

/**
 * Abre la sub-vista de colocación para UN documento. Lee sus bytes al abrir
 * (no antes) para no retener en memoria los bytes de documentos que la
 * persona nunca llega a colocar a mano.
 */
async function openPlacer(item: PreflightItem): Promise<void> {
  placing = item;
  placingBytes = null;
  placingLoadError = null;
  placingBoxPos = null;
  placingPageInfo = null;
  placingCurrentPage = 0;
  placingAutoPlaceDefault = true;
  placingWidgets = [];
  placingOverlapPending = false;
  placingScanIncomplete = false;
  try {
    const buf = await item.file.arrayBuffer();
    // La persona pudo cerrar la sub-vista (o abrir otra) mientras esto
    // resolvía: no pisar un `placing` más nuevo con estos bytes viejos.
    if (placing !== item) return;
    placingBytes = new Uint8Array(buf);
  } catch (e) {
    if (placing !== item) return;
    console.warn(
      `[lote] file read failed while opening placer: ${(e as Error)?.name ?? 'unknown'}`,
    );
    placingLoadError = t('lote.placer.load_error');
  }
}

function closePlacer(): void {
  placing = null;
  placingBytes = null;
  placingLoadError = null;
  placingBoxPos = null;
  placingPageInfo = null;
  placingCurrentPage = 0;
  placingWidgets = [];
  placingOverlapPending = false;
  placingScanIncomplete = false;
}

function onPlacingPageRender(info: { pdfWidth: number; pdfHeight: number }): void {
  placingPageInfo = { pdfWidth: info.pdfWidth, pdfHeight: info.pdfHeight };
}

/** Igual patrón que `boxPosBound`/`onBoxPositionChange` de Firmar.svelte: el
 *  overlay solo muestra la caja cuando está en la página que se está viendo. */
const placingBoxBound = $derived.by((): PlacerBoxPosition | null => {
  if (!placingBoxPos) return null;
  if (placingBoxPos.page !== placingCurrentPage + 1) return null;
  return placingBoxPos;
});

function onPlacingBoxChange(p: PlacerBoxPosition | null): void {
  if (!p) return;
  placingBoxPos = { ...p, page: placingCurrentPage + 1 };
  // Cualquier movimiento manual posterior al aviso de solape invalida esa
  // confirmación: hay que volver a evaluar el rect nuevo, no aceptar a ciegas
  // un segundo click sobre una posición distinta a la que se advirtió.
  placingOverlapPending = false;
}

/**
 * Default de colocación al abrir la sub-vista: igual estrategia que
 * `onSignaturesScanned` de Firmar.svelte (computeSmartPlacement esquivando
 * firmas previas VISIBLES de este mismo documento), con fallback a
 * `placeAtBottomLastPage` anclado a la última página en vez del centrado de
 * página 1 de BoxPlacer — coherente con `defaultLastPage` en el PdfPreview de
 * abajo.
 */
function onPlacingSignaturesScanned(scan: SignatureScan): void {
  placingWidgets = scan.widgets;
  // Se guarda la senal en vez de disparar el aviso aqui: el momento de pedir
  // confirmacion es cuando la persona intenta confirmar (`requestConfirm`), no
  // nada mas cargar el documento. La decision vive en un solo sitio, y ese
  // sitio esta probado en las dos direcciones (`needsOverlapConfirmation`).
  placingScanIncomplete = scan.incomplete;
  if (placingBoxPos) return;
  const smart = computeSmartPlacement({
    existing: scan.widgets,
    pageDims: scan.pageDims,
    defaultW: DEFAULT_SIG_BOX_W,
    defaultH: DEFAULT_SIG_BOX_H,
  });
  if (smart) {
    placingCurrentPage = smart.page - 1;
    placingBoxPos = smart;
    return;
  }
  if (scan.pageDims.length === 0) return;
  const lastPage = Math.max(...scan.pageDims.map((d) => d.page));
  const fallback = placeAtBottomLastPage({
    pageDims: scan.pageDims,
    lastPage,
    existing: scan.widgets,
  });
  placingCurrentPage = fallback.page - 1;
  placingBoxPos = fallback;
}

/**
 * Confirmar (o segunda confirmación tras el aviso de solape). No bloquea del
 * todo: la persona está mirando el canvas con el rect renderizado sobre el
 * PDF real, es la autoridad final, igual que en `/firmar` donde este mismo
 * caso no tiene ningún bloqueo — el aviso es una ayuda extra para el lote
 * (donde la atención por documento es menor), no una copia del guard
 * `empty_field_conflicts_with_prior_signature` de preflight-core.ts (ese
 * protege al pipeline AUTOMÁTICO; aquí el humano ya está viendo el PDF).
 */
function requestConfirm(): void {
  if (!placingBoxPos) return;
  const necesitaAviso = needsOverlapConfirmation({
    // Escaneo ciego sobre parte del documento: "no solapa" no es afirmable.
    scanIncomplete: placingScanIncomplete,
    overlapsKnown: overlapsExistingSignature(placingBoxPos, placingWidgets),
  });
  if (!placingOverlapPending && necesitaAviso) {
    placingOverlapPending = true;
    return;
  }
  commitPlacement(placingBoxPos);
}

/**
 * Publica el rect manual en `preflight`, reemplazando el item por identidad
 * de `File` (misma identidad que usan `splitPreflightWork`/`goToReview`).
 *
 * La conversión de página (1-based → 0-based) vive en `toManualPlacement`
 * (`../lib/batch/manualPlacement.ts`), probada por su propio unit test — ver
 * ese módulo para la trampa que documenta por qué existe.
 */
function commitPlacement(pos: PlacerBoxPosition): void {
  const item = placing;
  if (!item) return;
  const placement = toManualPlacement(pos);
  // Una recolocación manual borra cualquier badge de propagación previo — sin
  // esto, el spread de `...item` arrastraba un `propagated: 'exact'`/`'moved'`
  // viejo y la fila seguía diciendo "usa la posición que colocaste [en otro
  // documento]" después de que la persona la ajustó a mano ella misma.
  // `exactOptionalPropertyTypes` no admite `propagated: undefined` en el
  // spread — se excluye el campo del objeto en vez de asignárselo vacío.
  const { propagated: _oldPropagated, ...itemWithoutPropagation } = item;
  // QA post-merge 2026-08-03 (silent-failure-hunter): `toManualPlacement` no
  // lleva `rotate` (a diferencia del camino automático, que sí lo propaga —
  // `preflight-core.ts`), y publicar `placement` aquí SILENCIA la segunda
  // opinión del motor (`preflight.ts`: "si el llamante lo manda al firmante,
  // el worker ya no analiza nada"). En una página con `/Rotate`, el mismo
  // hueco conocido — `propagation.ts` ya rehúsa construir un hint sobre
  // páginas rotadas por esta trampa — dejaría la estampa fuera de sitio o
  // girada sin que ninguna guarda lo atrape. Si la página está rotada, NO se
  // publica el rect: la fila queda `ready` sin `placement`, que es
  // exactamente el camino ya documentado de "cae a colocación automática,
  // el motor decide de nuevo con su propia geometría".
  const geo = item.geometry?.find((g) => g.page === placement.page);
  const rotatedPage = geo !== undefined && geo.rotate !== 0;
  const updated: PreflightItem = rotatedPage
    ? { ...itemWithoutPropagation, status: 'ready' as const, page: placement.page, manual: true }
    : {
        ...itemWithoutPropagation,
        status: 'ready' as const,
        page: placement.page,
        placement,
        manual: true,
      };
  preflight = preflight.map((i) => (i.file === item.file ? updated : i));
  writtenSincePreflightSnapshot.add(item.file);
  closePlacer();
  propagationError = null;
  // Fire-and-forget, mismo patrón que `next()` con `goToReview`, pero con
  // `.catch()`: sin él, un rechazo de `propagateFrom` (p. ej. el Worker no
  // se pudo levantar) se perdía como unhandled rejection — invisible en una
  // app sin telemetría. El `finally` de `propagateFrom` ya limpia
  // `propagatingFiles` en ese caso; lo único que faltaba era avisar.
  void propagateFrom(updated).catch((e: unknown) => {
    console.error(`[lote] propagateFrom failed: ${(e as Error)?.name ?? 'unknown'}`);
    propagationError = t('lote.review.propagation_failed');
  });
}

// ---------- Paso 3: certificado, PIN y firma ----------
function onP12({ p12: buf, fileName }: { p12: ArrayBuffer; fileName: string }): void {
  p12 = buf;
  p12Name = fileName;
  p12Error = null;
}

async function startSigning(): Promise<void> {
  if (!p12 || pin === '' || signing) return;

  signing = true;
  cancelling = false;
  pinError = null;
  fatalError = null;
  signAbort = new AbortController();
  liveItems = [];

  // Un lote de 50 documentos son minutos con la pestaña abierta. Sin esto, un
  // despliegue nuevo recarga la app a media firma y se pierde el trabajo.
  holdReload();

  // El PIN se copia para la llamada y se borra del estado del componente en el
  // mismo turno: a partir de aquí no vive en ningún sitio que sobreviva.
  const pinForRun = pin;
  pin = '';

  try {
    // Los ficheros y los rects que el pre-vuelo calculó para ellos salen de una
    // sola llamada: así no hay dos listas que puedan dejar de corresponderse. El
    // firmante no vuelve a analizar lo que esta pantalla acaba de analizar, y
    // —más importante— lo que se firma es exactamente lo que se enseñó.
    const { files, visibleSigByIndex } = toBatchInput(signable);
    // Los MISMOS ajustes que usa `/firmar`. Sin esto el lote no hereda lo que la
    // persona configuró y, peor, el motor cae a su TSA por defecto —el directo a
    // freetsa.org, que en navegador siempre falla por CORS—: un intento de red
    // desperdiciado por documento y un aviso de «sin sello» que asustaba
    // describiendo el perfil B-B que esta app produce a propósito.
    const userSettings = getSettings();
    const res = await signBatchToZip(files, p12, pinForRun, {
      // 'auto' sigue siendo el respaldo: cubre a cualquier documento cuyo rect
      // el pre-vuelo decidiera no publicar.
      visibleSig: 'auto',
      visibleSigByIndex,
      signal: signAbort.signal,
      timestampEnabled: userSettings.tsaEnabled,
      tsaUrl: userSettings.tsaUrl,
      tsaTimeoutMs: userSettings.tsaTimeoutMs,
      ltvEnabled: userSettings.ltvEnabled,
      ltvArchiveEnabled: userSettings.ltvArchiveEnabled,
      ltvTimeoutMs: userSettings.ltvTimeoutMs,
      ocspUrl: userSettings.ocspUrl,
      onItemUpdate: (item) => {
        const next = liveItems.filter((i) => i.id !== item.id);
        liveItems = [...next, { ...item }];
      },
    });

    // Una corrida con al menos un PDF firmado; nunca un evento por documento.
    if (res.batch.succeeded > 0) pingUsage('lote');
    result = res;
    zipUrl = URL.createObjectURL(res.zip);
    // QA post-merge 2026-08-03 (silent-failure-hunter): el motor conserva a
    // propósito los bytes de todo documento que se firmó pero cuya escritura
    // al ZIP falló (`deliveryError`, "lifeline" — ver sign-queue.ts) para que
    // la persona no tenga que volver a pagar un round-trip de PKCS#7+TSA+OCSP.
    // Antes esos bytes llegaban hasta aquí y se tiraban sin ningún link de
    // descarga; ahora se ofrecen como recuperación individual (ver template,
    // fila `delivery_error`).
    recoveryUrls = new Map(
      res.excluded
        .filter((ex) => ex.reason === 'delivery_error')
        .map((ex) => res.batch.items.find((i) => i.id === ex.id))
        .filter((it): it is NonNullable<typeof it> => it?.result !== undefined)
        .map((it) => [
          it.id,
          URL.createObjectURL(
            new Blob([toArrayBuffer(it.result!.signedPdf)], { type: 'application/pdf' }),
          ),
        ]),
    );
    step = 4;
    // QA post-merge 2026-08-03 (code-reviewer, OWASP A02): `runBatchSign` ya
    // pone a cero su copia retenida del `.p12` en su propio `finally`
    // (`p12Master.fill(0)`, `sign-queue.ts`); este componente no honraba la
    // misma disciplina con la SUYA — el PIN se borra al usarlo (línea de
    // arriba), pero el contenedor cifrado del certificado sobrevivía en el
    // estado hasta `restart()` o hasta que muriera la pestaña. Tras un lote
    // exitoso no hay ningún flujo que lo reuse desde aquí.
    p12 = null;
  } catch (e) {
    // QA post-merge 2026-08-03 (silent-failure-hunter): este catch envuelve
    // TODO el lote (`signBatchToZip`) y es la única capa de este archivo sin
    // un solo `console.error` — sus módulos hermanos (preflight.ts,
    // preflight-bus.ts, sign-queue.ts) sí loguean, a propósito, porque la
    // consola es el único canal de diagnóstico que esta PWA tiene (cero
    // telemetría). Un lote de 50 documentos que muere aquí no dejaba NINGÚN
    // rastro. Se loguea solo el código/nombre — nunca datos del documento.
    const code = (e as { code?: string })?.code ?? '';
    const message = (e as Error)?.message ?? '';
    console.error(`[lote] batch sign failed: ${code || (e as Error)?.name || 'unknown'}`);
    // Antes: /pin|password|mac/i contra el MENSAJE clasificaba como "PIN
    // incorrecto" cualquier error cuyo texto contuviera "password" (p. ej.
    // un PDF cifrado) — mandaba a la persona a re-escribir un PIN que estaba
    // bien. Ahora: los códigos canónicos primero (mismo criterio que
    // `Firmar.svelte`), y el mensaje solo como respaldo con el patrón EXACTO
    // que `p12.ts` ya usa para detectar un fallo de MAC/contraseña real.
    if (
      code === 'pin_invalid' ||
      code === 'bad_pin' ||
      /MAC could not be verified|Invalid password|PKCS#12 MAC|integrity/i.test(message)
    ) {
      pinError = t('lote.error.bad_pin');
    } else if (e instanceof BatchZipCapacityError) {
      fatalError = t('lote.reject.zip_too_large');
    } else {
      fatalError = t('lote.error.generic');
    }
  } finally {
    signing = false;
    cancelling = false;
    signAbort = null;
    releaseReload();
  }
}

function cancelSigning(): void {
  if (!signAbort || cancelling) return;
  cancelling = true;
  signAbort.abort();
}

const signRows = $derived<LoteRow[]>(
  signable.map((item) => {
    const live = liveItems.find((l) => l.file === item.file);
    const status = live?.status ?? 'pending';
    const key = `lote.sign.status.${status}` as UIKey;
    return {
      id: item.id,
      name: stripControlChars(item.file.name),
      statusLabel: t(key),
      tone:
        status === 'done'
          ? ('ok' as const)
          : status === 'signing'
            ? ('busy' as const)
            : status === 'failed'
              ? ('err' as const)
              : status === 'needs_review'
                ? ('warn' as const)
                : ('neutral' as const),
    };
  }),
);

// ---------- Paso 4: resultado ----------
const doneTitle = $derived(
  result === null
    ? t('lote.done.title')
    : result.batch.succeeded === 0
      ? t('lote.done.title_none')
      : result.excluded.length > 0
        ? t('lote.done.title_partial')
        : t('lote.done.title'),
);

function exclusionLabel(reason: string): string {
  return t(`lote.done.excluded.${reason}` as UIKey);
}

/**
 * Mensaje técnico del motor, por documento. Un código a secas («no se pudo
 * firmar · incremental_update_failed») no deja a nadie —ni a quien firma ni a
 * quien recibe el reporte— averiguar QUÉ pasó. Los mensajes del firmante son
 * estructurales (hablan del PDF, no de su contenido), así que enseñarlos no
 * filtra nada del documento.
 */
const technicalDetail = $derived(
  new Map(
    (result?.batch.items ?? [])
      .filter((item) => item.error !== undefined)
      .map((item) => [item.id, item.error?.message ?? '']),
  ),
);

/**
 * Cuando lo que falla es la CARGA de un módulo de la propia app (un despliegue
 * nuevo que rotó los chunks con la pestaña abierta, o la caché del servidor de
 * desarrollo reconstruida debajo), el motor lo reporta documento a documento y
 * la lista acaba acusando a los PDFs de algo que no es suyo. Se nombra aparte:
 * el remedio —recargar— no tiene nada que ver con el documento.
 */
const appFailedToLoad = $derived(
  [...technicalDetail.values()].some((message) =>
    /dynamically imported module|Importing a module script failed|Failed to fetch/i.test(message),
  ),
);

function restart(): void {
  revokeZip();
  // Una revisión en vuelo de la tanda anterior no debe repintar la nueva.
  preflightRun += 1;
  preflightAbort?.abort();
  preflightRunning = false;
  // Simetría con `goToReview`/`back()`: si `restart()` alguna vez se invoca
  // desde otro punto del flujo con una propagación todavía corriendo, no debe
  // dejarla escribiendo sobre el lote que se está por vaciar.
  propagationRun += 1;
  propagationAbort?.abort();
  propagatingFiles = new Set();
  propagationError = null;
  step = 1;
  closePlacer();
  files = [];
  rejected = [];
  preflight = [];
  liveItems = [];
  result = null;
  downloaded = false;
  fatalError = null;
  reviewError = null;
  p12 = null;
  p12Name = '';
  pin = '';
  // Los avisos de la tanda anterior no valen para la nueva: dejarlos en pantalla
  // hace que la persona crea que ya falló algo antes de elegir un solo archivo.
  capacityError = null;
  p12Error = null;
  pinError = null;
}

/** Descarga individual de un documento cuyos bytes firmados sobrevivieron a
 *  un fallo de escritura al ZIP (`delivery_error` — ver `recoveryUrls`). */
function recoverSignedPdf(id: string, originalName: string): void {
  const url = recoveryUrls.get(id);
  if (!url) return;
  const a = document.createElement('a');
  a.href = url;
  a.download = zipEntryNameFor(originalName);
  a.click();
}

function revokeZip(): void {
  if (zipUrl) {
    URL.revokeObjectURL(zipUrl);
    zipUrl = null;
  }
  for (const url of recoveryUrls.values()) URL.revokeObjectURL(url);
  recoveryUrls = new Map();
}

onDestroy(() => {
  preflightAbort?.abort();
  propagationAbort?.abort();
  signAbort?.abort();
  // Si el componente muere a media firma, la retención tiene que soltarse o la
  // app deja de aceptar actualizaciones para siempre.
  if (signing) releaseReload();
  revokeZip();
  pin = '';
  // QA post-merge 2026-08-03 (silent-failure-hunter): el `.p12` (cifrado,
  // pero contenedor del certificado de firma de la persona) sobrevivía a la
  // firma exitosa — `runBatchSign` sí pone a cero su copia retenida
  // (`p12Master.fill(0)`, `sign-queue.ts`) en su propio `finally`; este
  // componente no honraba la misma disciplina con la suya.
  p12 = null;
});

/**
 * QA post-merge 2026-08-03 (silent-failure-hunter): el ZIP —única copia de
 * hasta 50 documentos legales YA firmados, con sello de tiempo ya
 * consumido— se destruía sin ningún aviso al cerrar/refrescar la pestaña
 * (ningún `beforeunload` en toda la app), navegar a `/firmar`, o pulsar
 * "Firmar otro lote" antes de descargar. El navegador ya trae el diálogo de
 * confirmación nativo para el primer caso; solo faltaba engancharlo.
 */
$effect(() => {
  const mustWarn = signing || (result !== null && !downloaded);
  if (!mustWarn) return;
  const handler = (e: BeforeUnloadEvent) => {
    e.preventDefault();
    e.returnValue = '';
  };
  window.addEventListener('beforeunload', handler);
  return () => window.removeEventListener('beforeunload', handler);
});

/** Misma guarda que `beforeunload`, para las dos salidas DENTRO de la app
 *  (reiniciar el lote / ir a `/firmar`) que `beforeunload` no cubre. */
function confirmLeaveIfUnsavedResult(): boolean {
  if (result === null || downloaded) return true;
  return confirm(t('lote.done.confirm_leave_unsaved'));
}

// ---------- Navegación ----------
function back(): void {
  // La sub-vista de colocación maneja su propio botón "Cancelar" (oculta el
  // footer del wizard mientras está abierta — ver `hideFooter` abajo), pero
  // esta guarda es la red de seguridad: cualquier otra vía que llegue a
  // `back()` con la sub-vista abierta la cierra en vez de retroceder un paso.
  if (placing !== null) {
    closePlacer();
    return;
  }
  if (step === 2) {
    preflightAbort?.abort();
    // Misma razón que el `propagationRun++`/`abort()` al principio de
    // `goToReview`: una propagación en vuelo no debe seguir escribiendo sobre
    // `preflight` una vez que la persona ya se fue del paso 2.
    propagationAbort?.abort();
    propagatingFiles = new Set();
    step = 1;
  } else if (step === 3) {
    step = 2;
  }
}

const canNext = $derived(
  step === 1
    ? files.length > 0
    : step === 2
      ? !preflightRunning && !isPropagating && signable.length > 0
      : false,
);

const nextLabel = $derived(
  step === 1
    ? // Sin documentos el CTA está deshabilitado, pero "Revisar los 0" se lee
      // como un error de la app. El rótulo neutro dice lo mismo sin chirriar.
      files.length === 0
      ? t('firmar.next')
      : tp('lote.select.continue', { n: files.length })
    : signable.length === 1
      ? t('lote.review.continue_one')
      : tp('lote.review.continue', { n: signable.length }),
);

function next(): void {
  // Sin el `catch`, un fallo aquí rechaza una promesa sin dueño: la pantalla se
  // queda exactamente igual, sin mensaje y sin avanzar, y la persona vuelve a
  // pulsar creyendo que no registró el clic. `goToReview` ya atrapa sus
  // propios fallos en `reviewError` (visible en el paso 2); esto solo cubre
  // lo que pueda escapar de ANTES de que `goToReview` llegue a su try (p.ej.
  // `assertBatchFitsZip` lanzando algo que no sea `BatchZipCapacityError`).
  if (step === 1) {
    void goToReview().catch((e: unknown) => {
      console.error(
        `[lote] next() failed before reaching step 2: ${(e as Error)?.name ?? 'unknown'}`,
      );
      fatalError = t('lote.error.generic');
    });
  } else if (step === 2) step = 3;
}
</script>

<svelte:head>
  <title>{t('lote.title')} — firmar.ec</title>
</svelte:head>

<WizardShell
  currentStep={step}
  totalSteps={STEPS.length}
  ariaLabel={t('lote.title')}
  canBack={step > 1 && !signing}
  {canNext}
  nextLabel={step <= 2 ? nextLabel : undefined}
  hideFooter={step >= 3 || placing !== null}
  onBack={back}
  onNext={next}
>
  {#snippet header()}
    <WizardProgress steps={STEPS} current={step} />
    <h1 class="mt-4 text-2xl sm:text-3xl font-semibold tracking-tight text-ink-900 dark:text-ink-50">
      {step === 4 ? doneTitle : t('lote.title')}
    </h1>
    {#if step === 1}
      <p class="mt-2 text-sm text-ink-600 dark:text-ink-400 max-w-prose">
        {tp('lote.subtitle', { max: EFFECTIVE_MAX_FILES })}
      </p>
    {/if}
  {/snippet}

  {#snippet body()}
    <!-- ============ Paso 1 — elegir documentos ============ -->
    {#if step === 1}
      <div class="flex flex-col gap-5">
        <DropLote
          onfiles={addFiles}
          max={EFFECTIVE_MAX_FILES}
          {maxSizeLabel}
          compact={files.length > 0}
          disabled={files.length >= EFFECTIVE_MAX_FILES}
        />

        {#if rejected.length > 0}
          <div class="rounded-xl border-l-4 border-warn-500 bg-warn-500/10 px-4 py-3" role="alert">
            <p class="text-sm font-medium text-ink-800 dark:text-ink-100">
              {tp('lote.reject.title', { n: rejected.length })}
            </p>
            <ul class="mt-1.5 space-y-0.5">
              {#each rejected.slice(0, 5) as bad, i (bad.file.name + bad.reason + i)}
                <li class="text-xs text-ink-700 dark:text-ink-300 truncate">
                  <span class="font-medium">{bad.file.name}</span>
                  <span>
                    — {bad.reason === 'file_too_large'
                      ? tp('lote.reject.file_too_large', { size: maxSizeLabel })
                      : bad.reason === 'too_many'
                        ? tp('lote.reject.too_many', { max: EFFECTIVE_MAX_FILES })
                        : t(`lote.reject.${bad.reason}` as UIKey)}
                  </span>
                </li>
              {/each}
              {#if rejected.length > 5}
                <li class="text-xs text-ink-600 dark:text-ink-400">+{rejected.length - 5}</li>
              {/if}
            </ul>
            <button
              type="button"
              onclick={() => (rejected = [])}
              class="mt-2 h-11 px-3 -ml-3 text-xs font-medium text-ink-700 dark:text-ink-200 rounded-md hover:bg-warn-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              {t('lote.reject.dismiss')}
            </button>
          </div>
        {/if}

        {#if capacityError}
          <p class="rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3 text-sm text-ink-800 dark:text-ink-100" role="alert">
            {capacityError}
          </p>
        {/if}

        {#if files.length === 0}
          <div class="text-center py-6">
            <p class="text-base font-medium text-ink-700 dark:text-ink-200">
              {t('lote.select.empty_title')}
            </p>
            <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
              {t('lote.select.empty_body')}
            </p>
          </div>
        {:else}
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-medium text-ink-700 dark:text-ink-200">
              {tp('lote.select.count', { n: files.length, max: EFFECTIVE_MAX_FILES })}
            </p>
            <button
              type="button"
              onclick={clearFiles}
              class="h-11 px-3 -mr-3 text-sm text-ink-600 dark:text-ink-400 rounded-md hover:text-err-500 hover:bg-ink-100 dark:hover:bg-ink-800 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              {t('lote.select.clear')}
            </button>
          </div>
          <LoteList rows={selectRows} onremove={removeFile} />
        {/if}
      </div>

    <!-- ============ Paso 2 — dónde va a quedar la firma ============ -->
    {:else if step === 2 && placing}
      <!-- ---- Sub-vista: colocador manual de UN documento ---- -->
      <div class="flex flex-col gap-5">
        <div>
          <h2 class="text-lg font-semibold text-ink-900 dark:text-ink-50">
            {t('lote.placer.title')}
          </h2>
          <p class="mt-1 text-sm text-ink-600 dark:text-ink-400 max-w-prose">
            {t('lote.placer.subtitle')}
          </p>
        </div>

        {#if placingLoadError}
          <p class="rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3 text-sm text-ink-800 dark:text-ink-100" role="alert">
            {placingLoadError}
          </p>
          <button
            type="button"
            onclick={closePlacer}
            class="self-start h-12 px-5 rounded-md border border-ink-300 dark:border-ink-700 bg-ink-50 dark:bg-ink-900 hover:bg-ink-100 dark:hover:bg-ink-800 text-ink-700 dark:text-ink-100 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          >
            {t('lote.placer.cancel')}
          </button>
        {:else if !placingBytes}
          <div
            class="flex items-center gap-3 rounded-xl bg-ink-100 dark:bg-ink-900 px-4 py-3"
            aria-live="polite"
          >
            <span class="i-lucide-loader-2 text-brand-500 spin-slow" aria-hidden="true"></span>
            <p class="text-sm text-ink-700 dark:text-ink-200">{t('lote.placer.loading')}</p>
          </div>
        {:else}
          {#snippet placerOverlay({ cssWidth, cssHeight }: { cssWidth: number; cssHeight: number })}
            {#if placingPageInfo}
              <BoxPlacer
                pdfPageSize={{ w: placingPageInfo.pdfWidth, h: placingPageInfo.pdfHeight }}
                canvasSize={{ w: cssWidth, h: cssHeight }}
                signerCN={''}
                position={placingBoxBound}
                onChange={onPlacingBoxChange}
                onConfirm={requestConfirm}
                autoPlaceDefault={placingAutoPlaceDefault}
              />
            {/if}
          {/snippet}
          <div class="pdf-stage-host">
            <PdfPreview
              pdfBytes={placingBytes}
              bind:currentPage={placingCurrentPage}
              onPageRender={onPlacingPageRender}
              onSignaturesScanned={onPlacingSignaturesScanned}
              overlay={placerOverlay}
              defaultLastPage
            />
          </div>

          {#if placingOverlapPending}
            <!-- El motivo importa: con el escaneo ciego NO hay ninguna firma
                 que solape, y decir que la hay es una afirmacion que la persona
                 puede desmentir mirando el canvas. Un aviso que miente entrena
                 a descartarlo — y aqui el descarte es irreversible. -->
            <p class="text-sm text-ink-800 dark:text-ink-100 rounded-xl border-l-4 border-warn-500 bg-warn-500/10 px-4 py-3" role="alert">
              {placingScanIncomplete
                ? t('lote.placer.scan_incomplete_warning')
                : t('lote.placer.overlap_warning')}
            </p>
          {/if}

          <div class="flex flex-wrap gap-3">
            <button
              type="button"
              onclick={closePlacer}
              class="h-12 px-5 rounded-md border border-ink-300 dark:border-ink-700 bg-ink-50 dark:bg-ink-900 hover:bg-ink-100 dark:hover:bg-ink-800 text-ink-700 dark:text-ink-100 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              {t('lote.placer.cancel')}
            </button>
            <button
              type="button"
              onclick={requestConfirm}
              disabled={!placingBoxPos}
              class="
                h-12 px-5 rounded-md bg-brand-500 hover:bg-brand-600 active:scale-[0.98]
                text-white font-medium transition-all duration-100
                disabled:opacity-40 disabled:cursor-not-allowed disabled:active:scale-100
                focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2
              "
              style="box-shadow: var(--shadow-rest);"
            >
              {placingOverlapPending ? t('lote.placer.overlap_confirm') : t('lote.placer.confirm')}
            </button>
          </div>
        {/if}
      </div>

    <!-- ============ Paso 2 — dónde va a quedar la firma ============ -->
    {:else if step === 2}
      <div class="flex flex-col gap-5">
        <div>
          <h2 class="text-lg font-semibold text-ink-900 dark:text-ink-50">
            {t('lote.review.title')}
          </h2>
          <p class="mt-1 text-sm text-ink-600 dark:text-ink-400 max-w-prose">
            {t('lote.review.subtitle')}
          </p>
        </div>

        {#if reviewError}
          <div class="rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3" role="alert">
            <p class="text-sm text-ink-800 dark:text-ink-100">{reviewError}</p>
            <button
              type="button"
              onclick={() => void goToReview()}
              class="mt-3 h-11 px-4 rounded-md bg-brand-500 hover:bg-brand-600 active:scale-[0.98] text-white text-sm font-medium transition-all duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
            >
              {t('lote.error.retry')}
            </button>
          </div>
        {/if}

        {#if preflightRunning}
          <div
            class="flex items-center gap-3 rounded-xl bg-ink-100 dark:bg-ink-900 px-4 py-3"
            aria-live="polite"
          >
            <span class="i-lucide-loader-2 text-brand-500 spin-slow" aria-hidden="true"></span>
            <p class="text-sm text-ink-700 dark:text-ink-200 font-mono">
              {tp('lote.review.progress', { n: preflight.length, total: files.length })}
            </p>
          </div>
        {/if}

        {#if propagationError}
          <div class="rounded-xl border-l-4 border-warn-500 bg-warn-500/10 px-4 py-3" role="alert">
            <p class="text-sm text-ink-800 dark:text-ink-100">{propagationError}</p>
            <button
              type="button"
              onclick={() => (propagationError = null)}
              class="mt-2 h-11 px-3 -ml-3 text-xs font-medium text-ink-700 dark:text-ink-200 rounded-md hover:bg-warn-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              {t('lote.reject.dismiss')}
            </button>
          </div>
        {/if}

        {#if preflight.length > 0}
          <LoteList rows={reviewRows} onremove={removeFromReview} />
        {/if}

        {#if !preflightRunning && excludedByPreflight.length > 0}
          <p class="text-sm text-ink-700 dark:text-ink-300 rounded-xl border-l-4 border-warn-500 bg-warn-500/10 px-4 py-3">
            {tp('lote.review.excluded_note', { n: excludedByPreflight.length })}
          </p>
        {/if}

        {#if !preflightRunning && signable.length === 0 && preflight.length > 0}
          <p class="text-sm text-ink-800 dark:text-ink-100 rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3" role="alert">
            {t('lote.review.all_excluded')}
          </p>
        {/if}
      </div>

    <!-- ============ Paso 3 — certificado, contraseña y firma ============ -->
    {:else if step === 3}
      <div class="flex flex-col gap-5">
        {#if !signing}
          <div>
            <h2 class="text-lg font-semibold text-ink-900 dark:text-ink-50">
              {t('lote.sign.title')}
            </h2>
            <p class="mt-1 text-sm text-ink-600 dark:text-ink-400 max-w-prose">
              {tp('lote.sign.subtitle', { n: signable.length })}
            </p>
          </div>

          {#if p12 === null}
            <DropP12 onp12={onP12} onerror={(key) => (p12Error = t(key))} />
            {#if p12Error}
              <p class="text-sm text-err-500" role="alert">{p12Error}</p>
            {/if}
          {:else}
            <div class="flex items-center gap-3 rounded-xl bg-ink-100 dark:bg-ink-900 px-4 py-3">
              <span class="i-lucide-shield-check text-brand-500" aria-hidden="true"></span>
              <p class="flex-1 min-w-0 truncate text-sm font-medium text-ink-800 dark:text-ink-100">
                {p12Name}
              </p>
              <button
                type="button"
                onclick={() => {
                  p12 = null;
                  p12Name = '';
                  pin = '';
                }}
                class="shrink-0 w-11 h-11 -mr-2 rounded-md flex items-center justify-center text-ink-500 hover:text-err-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                aria-label={t('firmar.back')}
              >
                <span class="i-lucide-x text-base" aria-hidden="true"></span>
              </button>
            </div>

            <PinInput bind:value={pin} error={pinError} onsubmit={startSigning} />

            <button
              type="button"
              onclick={startSigning}
              disabled={pin === ''}
              class="
                w-full h-12 rounded-md bg-brand-500 hover:bg-brand-600 active:scale-[0.98]
                text-white font-medium transition-all duration-100
                disabled:opacity-40 disabled:cursor-not-allowed disabled:active:scale-100
                focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2
              "
              style="box-shadow: var(--shadow-rest);"
            >
              {tp('lote.sign.cta', { n: signable.length })}
            </button>
          {/if}
        {:else}
          <!-- Firmando -->
          <div>
            <h2 class="text-lg font-semibold text-ink-900 dark:text-ink-50">
              {t('lote.sign.running_title')}
            </h2>
            <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
              {t('lote.sign.running_body')}
            </p>
          </div>

          <div
            role="progressbar"
            aria-label={tp('lote.aria.progress', { n: signedCount, total: signable.length })}
            aria-valuenow={signedCount}
            aria-valuemin={0}
            aria-valuemax={signable.length}
            class="flex flex-col gap-2"
          >
            <p class="text-sm font-mono text-ink-700 dark:text-ink-200" aria-live="polite">
              {tp('lote.sign.progress', { done: signedCount, total: signable.length })}
            </p>
            <div class="h-1.5 w-full rounded-full bg-ink-200 dark:bg-ink-800 overflow-hidden">
              <div
                class="h-full bg-brand-500 rounded-full"
                style="width: {signable.length > 0
                  ? (signedCount / signable.length) * 100
                  : 0}%; transition: width var(--motion-state-lg) var(--motion-curve);"
              ></div>
            </div>
          </div>

          <button
            type="button"
            onclick={cancelSigning}
            disabled={cancelling}
            class="
              self-start h-12 px-5 rounded-md
              border border-ink-300 dark:border-ink-700
              bg-ink-50 dark:bg-ink-900 hover:bg-ink-100 dark:hover:bg-ink-800
              text-ink-700 dark:text-ink-100 font-medium transition-colors
              disabled:opacity-40 disabled:cursor-not-allowed
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500
            "
          >
            {cancelling ? t('lote.sign.cancelling') : t('lote.sign.cancel')}
          </button>
        {/if}

        {#if fatalError}
          <p class="rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3 text-sm text-ink-800 dark:text-ink-100" role="alert">
            {fatalError}
          </p>
        {/if}

        <LoteList rows={signRows} />
      </div>

    <!-- ============ Paso 4 — descargar ============ -->
    {:else if step === 4 && result}
      <div class="flex flex-col gap-5">
        <p class="text-sm text-ink-700 dark:text-ink-200">
          {result.batch.succeeded === 1
            ? t('lote.done.summary_one')
            : tp('lote.done.summary', { n: result.batch.succeeded })}
        </p>

        {#if zipUrl && result.batch.succeeded > 0}
          <a
            href={zipUrl}
            download="documentos-firmados.zip"
            onclick={() => (downloaded = true)}
            class="
              inline-flex items-center justify-center gap-2 w-full h-14 rounded-md
              bg-brand-500 hover:bg-brand-600 active:scale-[0.98]
              text-white font-medium text-base transition-all duration-100
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2
            "
            style="box-shadow: var(--shadow-rest);"
          >
            <span class="i-lucide-download text-lg" aria-hidden="true"></span>
            <span>{tp('lote.done.download', { size: formatBytes(result.zip.size) })}</span>
          </a>
          {#if downloaded}
            <p class="text-sm text-ink-600 dark:text-ink-400 text-center" aria-live="polite">
              {t('lote.done.downloaded')}
            </p>
          {/if}
        {/if}

        <!-- Lo firmado PERO degradado: válido hoy, frágil mañana. Callarlo sería
             el fallo silencioso que el motor se molestó en poder reportar. -->
        {#if result.batch.succeededDegraded > 0}
          <div class="rounded-xl border-l-4 border-warn-500 bg-warn-500/10 px-4 py-3">
            <p class="text-sm font-medium text-ink-800 dark:text-ink-100">
              {tp('lote.done.degraded_title', { n: result.batch.succeededDegraded })}
            </p>
            <p class="mt-1 text-xs text-ink-700 dark:text-ink-300">
              {t('lote.done.degraded_body')}
            </p>
          </div>
        {/if}

        {#if appFailedToLoad}
          <div class="rounded-xl border-l-4 border-err-500 bg-err-500/10 px-4 py-3" role="alert">
            <p class="text-sm text-ink-800 dark:text-ink-100">
              {t('lote.error.stale_app')}
            </p>
            <button
              type="button"
              onclick={() => location.reload()}
              class="mt-3 h-11 px-4 rounded-md bg-brand-500 hover:bg-brand-600 active:scale-[0.98] text-white text-sm font-medium transition-all duration-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
            >
              {t('lote.error.reload')}
            </button>
          </div>
        {/if}

        {#if result.excluded.length > 0}
          <div>
            <p class="text-sm font-medium text-ink-800 dark:text-ink-100 mb-2">
              {tp('lote.done.excluded_title', { n: result.excluded.length })}
            </p>
            <LoteList
              rows={result.excluded.map((ex) => ({
                id: ex.id,
                name: stripControlChars(ex.originalName),
                statusLabel: exclusionLabel(ex.reason),
                detail: [reasonLabel(ex.detail), technicalDetail.get(ex.id)]
                  .filter((part) => part !== undefined && part !== '')
                  .join(' — '),
                tone: ex.reason === 'needs_review' ? ('warn' as const) : ('err' as const),
                action: recoveryUrls.has(ex.id)
                  ? {
                      label: t('lote.done.recover_signed'),
                      onClick: () => recoverSignedPdf(ex.id, ex.originalName),
                    }
                  : undefined,
              }))}
            />
          </div>
        {/if}

        <p class="text-xs text-ink-600 dark:text-ink-400">
          {t('lote.done.zip_note')}
        </p>

        <div class="flex flex-wrap gap-3">
          <button
            type="button"
            onclick={() => {
              if (confirmLeaveIfUnsavedResult()) restart();
            }}
            class="h-12 px-5 rounded-md border border-ink-300 dark:border-ink-700 bg-ink-50 dark:bg-ink-900 hover:bg-ink-100 dark:hover:bg-ink-800 text-ink-700 dark:text-ink-100 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          >
            {t('lote.done.restart')}
          </button>
          <button
            type="button"
            onclick={() => {
              if (confirmLeaveIfUnsavedResult()) push('/firmar');
            }}
            class="h-12 px-5 rounded-md text-ink-600 dark:text-ink-400 font-medium hover:text-ink-900 dark:hover:text-ink-50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          >
            {t('firmar.title')}
          </button>
        </div>
      </div>
    {/if}
  {/snippet}
</WizardShell>

<style>
  .pdf-stage-host {
    border-radius: var(--r-lg, 12px);
    overflow: hidden;
  }
  .spin-slow {
    animation: spin 900ms linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .spin-slow {
      animation-duration: 2.4s;
    }
  }
</style>
