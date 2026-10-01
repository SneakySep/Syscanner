import type { FastifyInstance } from 'fastify';

/**
 * Liveness and readiness.
 *
 *   /healthz  process is up (HTTP 200, no dependency checks)
 *   /readyz   dependencies are reachable; a non-200 causes the load balancer to
 *             remove this instance from rotation rather than send it traffic
 *             that will fail.
 */
export async function registerHealthRoutes(app: FastifyInstance): Promise<void> {
  app.get('/healthz', async () => ({ status: 'ok', service: 'syscanner-api' }));

  app.get('/readyz', async (_request, reply) => {
    const checks: Record<string, 'ok' | 'unavailable'> = {};

    try {
      await app.prisma.$queryRaw`SELECT 1`;
      checks.database = 'ok';
    } catch {
      checks.database = 'unavailable';
    }

    const ready = Object.values(checks).every((value) => value === 'ok');
    return reply.code(ready ? 200 : 503).send({ status: ready ? 'ready' : 'degraded', checks });
  });
}
