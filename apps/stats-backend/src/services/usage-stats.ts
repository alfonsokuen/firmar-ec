/**
 * usage-stats.ts — anonymous, privacy-safe usage counters for the public
 * landing stats strip (firmas / verificaciones / certificados).
 *
 * Signing and verification happen entirely client-side (zero-knowledge), so the
 * server can never *attest* that an event really occurred. These are therefore
 * best-effort usage tallies fed by an anonymous beacon — no PII.
 *
 * Each recorded event does two writes: it bumps the running total
 * (`usage_counters`, atomic ON CONFLICT upsert) and appends one row to
 * `stats_events` (used to derive the per-period time-series on read).
 */
import type { PrismaClient } from '@prisma/client';

// 'install' se registra y aparece en la serie temporal, pero NO se añade a
// `readTotals`: el shape público de GET /api/stats no cambia (lo consumen la
// landing y UsageCounter.svelte). La pregunta "¿la app se instala y crece?"
// se responde con /api/stats/series, que es donde vive el tiempo.
export type UsageKey = 'sign' | 'verify' | 'cert' | 'install' | 'lote';

/**
 * Record one anonymous event: atomically increment the running total and append
 * a per-event row for the series. Two sequential $executeRaw calls — no
 * transaction needed (a counter and an append-only log; a partial failure at
 * worst loses a single best-effort tally, never corrupts state).
 */
export async function recordEvent(prisma: PrismaClient, key: UsageKey): Promise<void> {
  await prisma.$executeRaw`
    INSERT INTO "usage_counters" ("key", "count", "updatedAt")
    VALUES (${key}, 1, CURRENT_TIMESTAMP)
    ON CONFLICT ("key") DO UPDATE
      SET "count" = "usage_counters"."count" + 1,
          "updatedAt" = CURRENT_TIMESTAMP
  `;
  await prisma.$executeRaw`
    INSERT INTO "stats_events" ("type") VALUES (${key})
  `;
}

export interface Totals {
  sign: number;
  verify: number;
  cert: number;
}

/** Read the running totals for the three known keys (default 0). */
export async function readTotals(prisma: PrismaClient): Promise<Totals> {
  const rows = await prisma.$queryRaw<Array<{ key: string; count: bigint }>>`
    SELECT "key", "count" FROM "usage_counters"
    WHERE "key" IN ('sign', 'verify', 'cert')
  `;
  const byKey = new Map(rows.map((r) => [r.key, Number(r.count)]));
  return {
    sign: byKey.get('sign') ?? 0,
    verify: byKey.get('verify') ?? 0,
    cert: byKey.get('cert') ?? 0,
  };
}
