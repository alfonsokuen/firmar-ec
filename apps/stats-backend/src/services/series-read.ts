/**
 * series-read.ts — derive the per-period time-series from the raw `stats_events`
 * log at read time.
 *
 * The KV worker pre-aggregated buckets on write; here we keep one row per event
 * and bucket on read instead. For the public landing's volumes a windowed range
 * scan (≤ a few thousand rows) over an indexed `ts` is cheap, and it keeps the
 * write path a trivial INSERT. Bucketing reuses the worker's pure date helpers
 * (series.ts) so the period labels stay byte-identical to the old contract.
 */
import type { PrismaClient } from '@prisma/client';
import {
  EVENT_TYPES,
  type EventType,
  type Granularity,
  bumpCount,
  dayStr,
  ecCivil,
  emptyCounts,
  periodKeyFor,
  periodsFor,
} from './series.js';
import { type Totals, readTotals } from './usage-stats.js';

const KNOWN_TYPES: ReadonlySet<string> = new Set(EVENT_TYPES);

export interface SeriesBucket {
  period: string;
  sign: number;
  verify: number;
  cert: number;
  install: number;
  lote: number;
}

export interface SeriesResult {
  granularity: Granularity;
  since: string;
  buckets: SeriesBucket[];
  totals: Totals;
}

/** Minimal logger surface (satisfied by Fastify's `app.log`). */
export interface SeriesLogger {
  warn: (obj: unknown, msg: string) => void;
}

/**
 * How far back to scan `stats_events` per granularity (ms). Each span comfortably
 * covers its read window with slack so a bucket on the oldest edge is never
 * starved by an off-by-one at the lower bound.
 */
const SPAN_MS: Record<Granularity, number> = {
  minute: 31 * 60_000,
  hour: 25 * 3_600_000,
  day: 31 * 86_400_000,
  week: 13 * 7 * 86_400_000,
  month: 371 * 86_400_000,
  year: 6 * 366 * 86_400_000,
};

export async function readSeries(
  prisma: PrismaClient,
  granularity: Granularity,
  now: number = Date.now(),
  log?: SeriesLogger,
): Promise<SeriesResult> {
  const periods = periodsFor(granularity, now);
  const lowerMs = now - SPAN_MS[granularity];

  const rows = await prisma.$queryRaw<Array<{ ts: Date; type: string }>>`
    SELECT "ts", "type" FROM "stats_events" WHERE "ts" >= ${new Date(lowerMs)}
  `;

  const map = new Map(periods.map((p) => [p, emptyCounts()]));
  const unknownTypes = new Set<string>();
  for (const row of rows) {
    // Skip unknown types so a stray row can never NaN-poison a bucket — but
    // record which ones so the skip is never silent: a newly-added event type
    // that forgot to update EVENT_TYPES would otherwise vanish from the series
    // with no trace ("the numbers don't add up" at 3am).
    if (!KNOWN_TYPES.has(row.type)) {
      unknownTypes.add(row.type);
      continue;
    }
    const pk = periodKeyFor(granularity, row.ts.getTime());
    const c = map.get(pk);
    if (c !== undefined) {
      map.set(pk, bumpCount(c, row.type as EventType));
    }
  }
  if (unknownTypes.size > 0 && log) {
    log.warn(
      { unknownTypes: [...unknownTypes], granularity },
      'series-read: skipped stats_events rows with unknown type(s)',
    );
  }

  const buckets: SeriesBucket[] = periods.map((p) => {
    const c = map.get(p) ?? emptyCounts();
    return {
      period: p,
      sign: c.sign,
      verify: c.verify,
      cert: c.cert,
      install: c.install,
      lote: c.lote,
    };
  });

  const totals = await readTotals(prisma);

  // "data since…" honesty note: the EC-local civil day of the very first event,
  // or today when the log is still empty.
  const minRows = await prisma.$queryRaw<Array<{ m: Date | null }>>`
    SELECT min("ts") AS m FROM "stats_events"
  `;
  const first = minRows[0]?.m ?? null;
  const since = first ? dayStr(ecCivil(first.getTime())) : dayStr(ecCivil(now));

  return { granularity, since, buckets, totals };
}
