import { prisma as prismaClient, type PrismaClient } from '@syscanner/db';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
  }
}

/**
 * Exposes the Prisma client on the Fastify instance and closes it on shutdown.
 *
 * Wrapped with `fastify-plugin` so the decorator is added to the root instance
 * rather than being scoped to this plugin's encapsulation context — routes
 * registered elsewhere would not see it otherwise.
 */
const prismaPlugin: FastifyPluginAsync = async (app: FastifyInstance) => {
  app.decorate('prisma', prismaClient);

  app.addHook('onClose', async () => {
    await prismaClient.$disconnect();
  });
};

export default fp(prismaPlugin, { name: 'prisma' });
