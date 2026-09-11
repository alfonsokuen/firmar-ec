import type { FastifyInstance } from 'fastify';
import RedisMock from 'ioredis-mock';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { buildServer } from '../src/server.js';

describe('HTTP limiter active on the real stats routes', () => {
  let app: FastifyInstance;
  let redis: InstanceType<typeof RedisMock>;
  const executeRaw = vi.fn(async () => 1);

  beforeEach(async () => {
    redis = new RedisMock();
    await redis.flushall();
    executeRaw.mockClear();
    app = await buildServer({
      overrides: {
        prisma: {
          $executeRaw: executeRaw,
          $queryRaw: async () => [],
          $disconnect: async () => {},
        } as never,
        redis: redis as never,
      },
    });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  test('100 lote requests cannot consume sign, verify or read HTTP allowance', async () => {
    for (let i = 0; i < 100; i++) {
      expect(
        (await app.inject({ method: 'POST', url: '/api/stats/event?type=lote' })).statusCode,
      ).toBe(204);
    }
    // Redis still limits writes to 20 events (two SQL statements per event).
    expect(executeRaw).toHaveBeenCalledTimes(40);
    const over = await app.inject({ method: 'POST', url: '/api/stats/event?type=lote' });
    expect(over.statusCode).toBe(429);
    expect(over.headers['retry-after']).toBeDefined();
    for (const type of ['sign', 'verify', 'cert', 'install']) {
      expect(
        (await app.inject({ method: 'POST', url: `/api/stats/event?type=${type}` })).statusCode,
      ).toBe(204);
    }
    expect(executeRaw).toHaveBeenCalledTimes(48);
    expect((await app.inject({ method: 'GET', url: '/api/stats' })).statusCode).toBe(200);
  });

  test('JSON and query share the same allowance and query takes precedence', async () => {
    for (let i = 0; i < 100; i++) {
      expect(
        (await app.inject({ method: 'POST', url: '/api/stats/event', payload: { type: 'sign' } }))
          .statusCode,
      ).toBe(204);
    }
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/stats/event?type=sign',
          payload: { type: 'verify' },
        })
      ).statusCode,
    ).toBe(429);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/stats/event?type=verify',
          payload: { type: 'sign' },
        })
      ).statusCode,
    ).toBe(204);
  });

  test('arbitrary invalid names share one HTTP allowance and never create Redis keys', async () => {
    for (let i = 0; i < 100; i++) {
      expect(
        (await app.inject({ method: 'POST', url: `/api/stats/event?type=invalid-${i}` }))
          .statusCode,
      ).toBe(422);
    }
    expect(
      (await app.inject({ method: 'POST', url: '/api/stats/event?type=another-invalid' }))
        .statusCode,
    ).toBe(429);
    expect(await redis.keys('rl:stats:*')).toEqual([]);
    expect(executeRaw).not.toHaveBeenCalled();
    expect(
      (await app.inject({ method: 'POST', url: '/api/stats/event?type=sign' })).statusCode,
    ).toBe(204);
  });

  test('read HTTP protection remains active after 100 requests', async () => {
    for (let i = 0; i < 100; i++) {
      expect((await app.inject({ method: 'GET', url: '/api/stats' })).statusCode).toBe(200);
    }
    expect((await app.inject({ method: 'GET', url: '/api/stats' })).statusCode).toBe(429);
  });

  test('invalid query cannot select the valid body bucket; duplicate query types are invalid', async () => {
    for (const url of [
      '/api/stats/event?type=',
      '/api/stats/event?type=nope',
      '/api/stats/event?type=sign&type=verify',
    ]) {
      const res = await app.inject({ method: 'POST', url, payload: { type: 'sign' } });
      expect(res.statusCode).toBe(422);
      expect(res.headers['x-ratelimit-limit']).toBe('100');
    }
    expect(await redis.keys('rl:stats:*')).toEqual([]);
    expect(executeRaw).not.toHaveBeenCalled();
    const valid = await app.inject({
      method: 'POST',
      url: '/api/stats/event',
      payload: { type: 'sign' },
    });
    expect(valid.statusCode).toBe(204);
    expect(valid.headers['x-ratelimit-remaining']).toBe('99');
  });

  test('trailing slash and case variants do not alias the event route', async () => {
    for (const url of ['/api/stats/event/?type=sign', '/api/stats/Event?type=sign']) {
      expect((await app.inject({ method: 'POST', url })).statusCode).toBe(404);
    }
    expect(executeRaw).not.toHaveBeenCalled();
  });
});
