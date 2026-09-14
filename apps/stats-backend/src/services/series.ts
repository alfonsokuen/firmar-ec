/**
 * series.ts — pure date-bucketing + storage codec for the firmar.ec usage
 * time-series.
 *
 * No Workers/KV types here on purpose: everything is pure (epoch ms / strings
 * in, values out) so it runs and tests under plain Node. main.ts wires these to
 * KV.
 *
 * Storage: ONE combined key per (granularity, period) — `b:<g>:<period>` — whose
 * value is `{s,v,c}` (sign/verify/cert). Combining the three types into a single
 * key keeps a read cheap: the densest view (30 days) is 30 gets + a few, well
 * under the per-request subrequest budget on any Workers plan (a per-type layout
 * would be 90+). Buckets are pre-aggregated on write rather than derived on read,
 * so week/month/year never sum daily keys. KV has no atomic increment, so these
 * are best-effort social-proof tallies — same posture as the existing totals.
 *
 * Time zone: America/Guayaquil is a fixed UTC−5 (no DST), so a constant offset
 * is exact. "The day" therefore matches the local calendar day in Ecuador, not
 * UTC, which matters for a counter people read against their own clock.
 */

export type EventType = 'sign' | 'verify' | 'cert' | 'install' | 'lote';
export const EVENT_TYPES: readonly EventType[] = ['sign', 'verify', 'cert', 'install', 'lote'];

export type Granularity = 'minute' | 'hour' | 'day' | 'week' | 'month' | 'year';
export const GRANULARITIES: readonly Granularity[] = [
  'minute',
  'hour',
  'day',
  'week',
  'month',
  'year',
];

export function isGranularity(x: unknown): x is Granularity {
  return typeof x === 'string' && (GRANULARITIES as readonly string[]).includes(x);
}

/** How many buckets each granularity returns (newest last). */
export const WINDOW: Record<Granularity, number> = {
  minute: 30,
  hour: 24,
  day: 30,
  week: 12,
  month: 12,
  year: 5,
};

/** Single-letter KV namespace per granularity: b:<g>:<period>. */
const PREFIX: Record<Granularity, string> = {
  minute: 'i',
  hour: 'h',
  day: 'd',
  week: 'w',
  month: 'm',
  year: 'y',
};

/**
 * TTLs for the high-cardinality granularities. Unlike day/week/month/year (kept
 * forever), minute (~1440/day) and hour (~24/day) keys would accumulate without
 * bound, so they self-expire well past their read window (30 min / 24 h).
 * Returns null for the permanent granularities.
 */
const MINUTE_TTL_S = 7200; // 2 h
const HOUR_TTL_S = 345_600; // 4 days
export function ttlFor(g: Granularity): number | null {
  if (g === 'minute') return MINUTE_TTL_S;
  if (g === 'hour') return HOUR_TTL_S;
  return null;
}

const EC_OFFSET_MS = 5 * 60 * 60 * 1000; // UTC−5, Guayaquil (no DST)
const DAY_MS = 86_400_000;

interface Civil {
  y: number;
  m: number; // 1-12
  d: number; // 1-31
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Civil date (Y/M/D) in Ecuador local time for a given epoch ms. */
export function ecCivil(epochMs: number): Civil {
  const shifted = new Date(epochMs - EC_OFFSET_MS);
  return { y: shifted.getUTCFullYear(), m: shifted.getUTCMonth() + 1, d: shifted.getUTCDate() };
}

function civilToUtcMs(c: Civil): number {
  return Date.UTC(c.y, c.m - 1, c.d);
}

function utcMsToCivil(ms: number): Civil {
  const d = new Date(ms);
  return { y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate() };
}

export function dayStr(c: Civil): string {
  return `${c.y}-${pad2(c.m)}-${pad2(c.d)}`;
}

export function monthStr(c: Civil): string {
  return `${c.y}-${pad2(c.m)}`;
}

// Minute/hour keys carry the time-of-day (EC-local). Built from an already
// EC-shifted ms so periodsFor can step back by minute/hour cleanly.
function fmtMinute(shiftedMs: number): string {
  const d = new Date(shiftedMs);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`;
}
function fmtHour(shiftedMs: number): string {
  const d = new Date(shiftedMs);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}`;
}

export function minuteStr(epochMs: number): string {
  return fmtMinute(epochMs - EC_OFFSET_MS);
}
export function hourStr(epochMs: number): string {
  return fmtHour(epochMs - EC_OFFSET_MS);
}

function parseDay(s: string): Civil {
  const [y, m, d] = s.split('-').map(Number);
  return { y, m, d };
}

/** Monday (ISO week start) of the EC-local week containing epochMs, as YYYY-MM-DD. */
export function weekStartStr(epochMs: number): string {
  const base = civilToUtcMs(ecCivil(epochMs));
  const dow = new Date(base).getUTCDay(); // 0=Sun..6=Sat
  const backToMonday = (dow + 6) % 7;
  return dayStr(utcMsToCivil(base - backToMonday * DAY_MS));
}

/** Period label for a single event at epochMs, per granularity. */
export function periodKeyFor(g: Granularity, epochMs: number): string {
  const c = ecCivil(epochMs);
  switch (g) {
    case 'minute':
      return minuteStr(epochMs);
    case 'hour':
      return hourStr(epochMs);
    case 'day':
      return dayStr(c);
    case 'week':
      return weekStartStr(epochMs);
    case 'month':
      return monthStr(c);
    case 'year':
      return String(c.y);
  }
}

/** The ordered list of period labels (oldest→newest) for a read window. */
export function periodsFor(g: Granularity, epochMs: number): string[] {
  const n = WINDOW[g];
  const out: string[] = [];
  if (g === 'minute') {
    const STEP = 60_000;
    const shifted = epochMs - EC_OFFSET_MS;
    const floored = shifted - (shifted % STEP);
    for (let i = n - 1; i >= 0; i--) out.push(fmtMinute(floored - i * STEP));
  } else if (g === 'hour') {
    const STEP = 3_600_000;
    const shifted = epochMs - EC_OFFSET_MS;
    const floored = shifted - (shifted % STEP);
    for (let i = n - 1; i >= 0; i--) out.push(fmtHour(floored - i * STEP));
  } else if (g === 'day') {
    const base = civilToUtcMs(ecCivil(epochMs));
    for (let i = n - 1; i >= 0; i--) out.push(dayStr(utcMsToCivil(base - i * DAY_MS)));
  } else if (g === 'week') {
    const base = civilToUtcMs(parseDay(weekStartStr(epochMs)));
    for (let i = n - 1; i >= 0; i--) out.push(dayStr(utcMsToCivil(base - i * 7 * DAY_MS)));
  } else if (g === 'month') {
    let { y, m } = ecCivil(epochMs);
    for (let i = 0; i < n; i++) {
      out.push(`${y}-${pad2(m)}`);
      m -= 1;
      if (m === 0) {
        m = 12;
        y -= 1;
      }
    }
    out.reverse();
  } else {
    const { y } = ecCivil(epochMs);
    for (let i = n - 1; i >= 0; i--) out.push(String(y - i));
  }
  return out;
}

// ── Combined per-period storage ──────────────────────────────────────────────

export interface Counts {
  sign: number;
  verify: number;
  cert: number;
  install: number;
  lote: number;
}

export function emptyCounts(): Counts {
  return { sign: 0, verify: 0, cert: 0, install: 0, lote: 0 };
}

/** Full KV key for a period's combined counts. */
export function combinedKey(g: Granularity, period: string): string {
  return `b:${PREFIX[g]}:${period}`;
}

/** Keys (one per granularity) an event at epochMs must touch. */
export function eventCombinedKeys(epochMs: number): { g: Granularity; key: string }[] {
  return GRANULARITIES.map((g) => ({ g, key: combinedKey(g, periodKeyFor(g, epochMs)) }));
}

function toCount(x: unknown): number {
  const v = Number(x);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

/** Parse a stored combined value (compact `{s,v,c}`); tolerant of null/garbage. */
export function parseCounts(raw: string | null): Counts {
  if (!raw) return emptyCounts();
  try {
    const o = JSON.parse(raw) as Record<string, unknown>;
    // OJO: este codec (parseCounts/serializeCounts) es LEGADO de la era KV y hoy
    // NO lo llama nadie fuera de los tests — la serie se bucketiza en lectura
    // desde `stats_events` (series-read.ts), que solo usa bumpCount/emptyCounts.
    // Se mantiene tolerante por si vuelve a usarse: `i` no existe en los valores
    // guardados antes de 2026-08-24 y toCount(undefined) da 0.
    return {
      sign: toCount(o.s),
      verify: toCount(o.v),
      cert: toCount(o.c),
      install: toCount(o.i),
      lote: toCount(o.l),
    };
  } catch {
    return emptyCounts();
  }
}

export function serializeCounts(c: Counts): string {
  return JSON.stringify({ s: c.sign, v: c.verify, c: c.cert, i: c.install, l: c.lote });
}

/** Immutably increment one event type in a counts record. */
export function bumpCount(c: Counts, type: EventType): Counts {
  return { ...c, [type]: c[type] + 1 };
}
