import { PrismaClient } from '@prisma/client';

/**
 * Single PrismaClient per process.
 *
 * In development Next.js hot-reloads modules, which would otherwise create a new
 * connection pool on every reload and exhaust Postgres connections.
 */
const globalForPrisma = globalThis as unknown as { __syscannerPrisma?: PrismaClient };

export function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['warn', 'error']
        : ['error'],
  });
}

export const prisma: PrismaClient = globalForPrisma.__syscannerPrisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.__syscannerPrisma = prisma;
}
