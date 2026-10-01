import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import Fastify, { type FastifyInstance } from 'fastify';

import { loadConfig, type AppConfig } from './config';
import prismaPlugin from './plugins/prisma';
import queuePlugin from './plugins/queues';
import { registerFindingRoutes } from './routes/findings';
import { registerHealthRoutes } from './routes/health';
import { registerRepositoryRoutes } from './routes/repositories';
import { registerScanRoutes } from './routes/scans';
import { TenantResolutionError } from './tenant';

export interface BuildAppOptions {
  config?: AppConfig;
  logger?: boolean;
}

/**
 * Creates a fully wired Fastify instance without binding a port.
 *
 * Keeping construction separate from `listen` is what makes the API testable with
 * `app.inject()` and lets the same factory serve production, tests and dev.
 */
export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();

  const app = Fastify({
    logger: options.logger ?? true,
    trustProxy: true,
    // Cap request bodies: the API never accepts file uploads, so anything large is
    // either a bug or an attack.
    bodyLimit: 1_048_576,
    requestIdHeader: 'x-request-id',
  });

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, {
    origin: config.WEB_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  });
  await app.register(rateLimit, {
    max: config.RATE_LIMIT_PER_MINUTE,
    timeWindow: '1 minute',
    // Per tenant, not per IP: a whole customer behind one NAT must not be throttled
    // as though it were a single abuser.
    keyGenerator: (request) => {
      const header = request.headers['x-organization-id'];
      const organizationId = Array.isArray(header) ? header[0] : header;
      return organizationId ?? request.ip;
    },
  });

  await app.register(prismaPlugin);
  await app.register(queuePlugin);

  // Uniform error envelope. Internal errors never leak stack traces or SQL.
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof TenantResolutionError) {
      return reply
        .code(error.statusCode)
        .send({ error: { code: error.code, message: error.message } });
    }

    if (error instanceof ZodError) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: error.issues
            .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
            .join('; '),
        },
      });
    }

    // Fastify types the handler argument loosely, so narrow defensively rather
    // than asserting a shape the runtime may not provide.
    const shaped = error as { statusCode?: number; code?: string; message?: string };
    const statusCode = typeof shaped.statusCode === 'number' ? shaped.statusCode : 500;

    if (statusCode >= 500) {
      request.log.error({ err: error }, 'unhandled request error');
    }

    return reply.code(statusCode).send({
      error: {
        code: statusCode >= 500 ? 'INTERNAL_ERROR' : (shaped.code ?? 'BAD_REQUEST'),
        message: statusCode >= 500 ? 'An internal error occurred.' : (shaped.message ?? 'Bad request.'),
      },
    });
  });

  app.setNotFoundHandler((_request, reply) =>
    reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Route not found.' } }),
  );

  await registerHealthRoutes(app);
  await registerRepositoryRoutes(app);
  await registerScanRoutes(app);
  await registerFindingRoutes(app);

  return app;
}
