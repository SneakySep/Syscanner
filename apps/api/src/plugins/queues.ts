import { createRedisConnection, ScanQueueProducer } from '@syscanner/queue';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    queues: ScanQueueProducer;
  }
}

/**
 * Owns the Redis connection and the BullMQ producer for the API's lifetime.
 *
 * The API is the only service that schedules scans, so all enqueueing is funnelled
 * through this one decorator — which makes rate-limiting and metering a single
 * concern instead of something every route has to remember.
 */
const queuePlugin: FastifyPluginAsync = async (app: FastifyInstance) => {
  const connection = createRedisConnection();
  const producer = new ScanQueueProducer(connection);

  app.decorate('queues', producer);

  app.addHook('onClose', async () => {
    await producer.close();
  });
};

export default fp(queuePlugin, { name: 'queues' });
