import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import type { FastifyBaseLogger } from 'fastify';
import type { Redis } from 'ioredis';
import pino from 'pino';
import { type Env, loadEnv } from './env.js';
import { registerErrorHandler } from './lib/errors.js';
import { loggerOptions } from './logger.js';
import prismaPlugin from './plugins/prisma.js';
import redisPlugin from './plugins/redis.js';
import healthRoutes from './routes/health.js';
import statsRoutes from './routes/stats.js';

export interface BuildServerOpts {
  /** Test only: skip the HTTP limiter plugin (Redis accounting limits remain). */
  disableRateLimit?: boolean;
  /** Override env (test only). */
  env?: Env;
  /** Test overrides — pass mocks to skip real plugin construction. */
  overrides?: {
    prisma?: PrismaClient;
    redis?: Redis;
  };
  /**
   * Destino del logger (solo test). Existe para poder afirmar sobre lo que de
   * verdad se escribe en el log de la ruta real, no sobre el objeto de config:
   * el aviso de privacidad promete que la IP del cliente no queda registrada, y
   * esa promesa solo se puede verificar leyendo la salida.
   */
  logStream?: NodeJS.WritableStream;
}

export async function buildServer(opts: BuildServerOpts = {}): Promise<FastifyInstance> {
  const env = opts.env ?? loadEnv();
  // Fastify 5 distingue `logger` (objeto de configuracion) de `loggerInstance`
  // (logger ya construido). El seam de test usa el segundo; produccion, el primero.
  const app = Fastify({
    ...(opts.logStream
      ? // El cast mantiene el tipo ancho de FastifyInstance: pasar una instancia
        // concreta de pino hace que Fastify infiera Logger<...> en vez de
        // FastifyBaseLogger y rompe la firma declarada de buildServer.
        { loggerInstance: pino(loggerOptions, opts.logStream) as FastifyBaseLogger }
      : { logger: loggerOptions }),
    disableRequestLogging: false,
    trustProxy: true,
    bodyLimit: 64 * 1024, // 64KB — tiny JSON beacons only
  });

  registerErrorHandler(app);

  await app.register(helmet, {
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-site' },
  });
  await app.register(cors, {
    // `\.firmar\.ec$` covers subdomains (app./www./inbox.); the apex landing
    // origin `firmar.ec` has no leading dot, so list it explicitly.
    origin: [
      /\.firmar\.ec$/,
      'https://firmar.ec',
      'http://localhost:5173',
      'http://localhost:4321',
    ],
    credentials: false,
  });

  if (!opts.disableRateLimit) {
    await app.register(rateLimit, {
      max: 100,
      timeWindow: '1 minute',
    });
  }

  // Infra plugins (mocks override real construction for tests).
  if (opts.overrides?.prisma) {
    await app.register(prismaPlugin, { client: opts.overrides.prisma });
  } else {
    await app.register(prismaPlugin, {});
  }
  if (opts.overrides?.redis) {
    await app.register(redisPlugin, { client: opts.overrides.redis });
  } else {
    await app.register(redisPlugin, { url: env.REDIS_URL });
  }

  await app.register(healthRoutes);
  await app.register(statsRoutes, { env });

  return app;
}
