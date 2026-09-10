/**
 * Public usage stats for the firmar.ec landing — drop-in replacement for the
 * KV stats worker (tools/stats-worker). Same contract, swarm-hosted, backed by
 * Postgres + Redis instead of KV.
 *
 * GET  /api/stats               → { pdfsSigned, signaturesVerified, certificatesValidated, certificatesIssued }
 * GET  /api/stats/series        → { granularity, since, buckets:[{period,sign,verify,cert,install,lote}], totals }
 * POST /api/stats/event         → 204 (anonymous beacon; sign | verify | cert | install | lote)
 *
 * The beacon is anonymous and best-effort: signing/verification are client-side
 * by design, so the server cannot attest them. We rate-limit per IP to resist
 * trivial inflation and silently drop (204) over-limit hits rather than count
 * them. GET is cached briefly to shield the DB from landing traffic spikes.
 */
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Env } from '../env.js';
import { StatsError } from '../lib/errors.js';
import { checkAndConsume } from '../services/rate-limit.js';
import { readSeries } from '../services/series-read.js';
import { type Granularity, isGranularity } from '../services/series.js';
import { type Totals, readTotals, recordEvent } from '../services/usage-stats.js';

const EventBody = z.object({ type: z.enum(['sign', 'verify', 'cert', 'install', 'lote']) });

const CACHE_TTL_MS = 60_000;

// Edge/browser cache freshness per granularity: live-ish granularities short,
// trends longer — mirrors the worker.
const SERIES_MAX_AGE: Record<Granularity, number> = {
  minute: 30,
  hour: 60,
  day: 300,
  week: 300,
  month: 300,
  year: 300,
};

interface StatsResponse {
  pdfsSigned: number;
  signaturesVerified: number;
  certificatesValidated: number;
  certificatesIssued: null;
}

function toResponse(totals: Totals): StatsResponse {
  return {
    pdfsSigned: totals.sign,
    signaturesVerified: totals.verify,
    certificatesValidated: totals.cert,
    certificatesIssued: null,
  };
}

export interface StatsRoutesOpts {
  env: Env;
}

export default async function statsRoutes(
  app: FastifyInstance,
  opts: StatsRoutesOpts,
): Promise<void> {
  const { env } = opts;
  // Disable caching under test so increment→read is deterministic.
  const useCache = env.NODE_ENV !== 'test';
  let cache: { at: number; data: StatsResponse } | null = null;

  app.post('/api/stats/event', async (req, reply) => {
    // Accept the type from a query param (so navigator.sendBeacon can fire a
    // body-less, CORS-preflight-free POST) or a JSON body.
    const fromQuery = (req.query as { type?: unknown } | undefined)?.type;
    const fromBody = (req.body as { type?: unknown } | null)?.type;
    const parsed = EventBody.safeParse({ type: fromQuery ?? fromBody });
    if (!parsed.success) {
      throw new StatsError(
        'invalid_input',
        "type must be 'sign', 'verify', 'cert', 'install' or 'lote'",
      );
    }

    // 20 events/hour per type. Named per-IP, but `req.ip` resolves to an internal
    // address behind the tunnel, so each type has a bucket shared by every
    // visitor — see the drop warning below.
    // Fail OPEN and LOUD: if Redis is down the limiter is skipped (we'd rather
    // count an event than 500 the beacon or silently drop it).
    try {
      const rl = await checkAndConsume(app.redis.client, {
        key: `rl:stats:${req.ip || 'unknown'}:${parsed.data.type}`,
        capacity: 20,
        refillPerSec: 20 / 3_600,
      });
      if (!rl.ok) {
        // Accept-and-ignore towards the client: don't leak limiter state.
        // But NEVER drop it silently on our side. `req.ip` is an internal
        // address of our own overlay network (all public traffic arrives
        // through the tunnel), so this bucket is GLOBAL, not per-visitor:
        // once it empties, real events stop being counted and the published
        // figure falls short with nothing to show for it. Measured against
        // production 2026-08-24: 1498/1498 logged requests carried a private
        // address, 0 public. This warning is the only trace that a real
        // operation went uncounted.
        app.log.warn(
          { retryAfterS: rl.retryAfterS, type: parsed.data.type },
          'stats event DROPPED by the shared rate-limit bucket — published counters now under-report',
        );
        return reply.code(204).send();
      }
    } catch (e) {
      app.log.warn({ err: e }, 'stats rate-limit unavailable, failing open');
    }

    await recordEvent(app.prisma, parsed.data.type);
    cache = null; // next GET recomputes
    return reply.code(204).send();
  });

  app.get('/api/stats', async (_req, reply) => {
    reply.header('cache-control', 'public, max-age=60');
    if (useCache && cache && Date.now() - cache.at < CACHE_TTL_MS) {
      return reply.code(200).send(cache.data);
    }
    const data = toResponse(await readTotals(app.prisma));
    if (useCache) cache = { at: Date.now(), data };
    return reply.code(200).send(data);
  });

  app.get('/api/stats/series', async (req, reply) => {
    const granularity = (req.query as { granularity?: unknown } | undefined)?.granularity;
    if (!isGranularity(granularity)) {
      return reply.code(422).send({ error: 'invalid_input' });
    }
    reply.header('cache-control', `public, max-age=${SERIES_MAX_AGE[granularity]}`);
    return reply.code(200).send(await readSeries(app.prisma, granularity, undefined, app.log));
  });
}
