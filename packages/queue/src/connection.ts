import { Redis } from 'ioredis';

/**
 * BullMQ requires `maxRetriesPerRequest: null` on the connection it manages,
 * otherwise blocking commands throw on transient blips.
 */
export function createRedisConnection(url: string = process.env.REDIS_URL ?? 'redis://localhost:6379'): Redis {
  const useTls = process.env.REDIS_TLS === 'true';

  return new Redis(url, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
    ...(useTls ? { tls: { rejectUnauthorized: true } } : {}),
  });
}

/** Redis key namespace. Keeps Syscanner from colliding with other tenants of a shared Redis. */
export const REDIS_PREFIX = 'syscanner';

/** Pub/sub channel used to stream scan progress to the browser over SSE. */
export function scanProgressChannel(scanId: string): string {
  return `${REDIS_PREFIX}:scan-progress:${scanId}`;
}
