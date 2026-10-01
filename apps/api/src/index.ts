import { buildApp } from './app';
import { loadConfig } from './config';

/**
 * API process entrypoint.
 *
 * Shutdown is ordered deliberately: stop accepting new connections first, then
 * drain in-flight requests, then let the `onClose` hooks release the Prisma pool
 * and the Redis connection. A hard kill would abandon queued jobs mid-flight.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const app = await buildApp({ config });

  let shuttingDown = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;

    app.log.info({ signal }, 'shutting down');
    try {
      await app.close();
      process.exitCode = 0;
    } catch (error) {
      app.log.error({ err: error }, 'error during shutdown');
      process.exitCode = 1;
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ port: config.API_PORT, host: config.API_HOST });
}

if (require.main === module) {
  main().catch((error: unknown) => {
    console.error('Failed to start the API:', error);
    process.exitCode = 1;
  });
}

export { buildApp };
