import { Worker, type Job } from 'bullmq';

import { prisma } from '@syscanner/db';
import { createLogger } from '@syscanner/logger';
import {
  CONSUMER_QUEUES,
  createRedisConnection,
  orchestrateScanJobSchema,
  parseJobPayload,
  QUEUE_NAMES,
  ScanQueueProducer,
  scanRepositoryJobSchema,
  scannerJobSchema,
  type NotifyJob,
} from '@syscanner/queue';

import { loadWorkerConfig, type WorkerConfig } from './config';
import { orchestrateScanJob } from './processors/orchestrateScan';
import { runScannerJob } from './processors/runScanner';
import { scanRepositoryJob } from './processors/scanRepository';
import { DockerSandboxProvider } from './sandbox/dockerProvider';
import { cleanupScanScratch, sweepStaleScratch } from './scratch';

/**
 * Worker process entrypoint.
 *
 * One process consumes every queue. Concurrency is bounded by
 * `WORKER_CONCURRENCY`, and each scanner job spawns exactly one sandbox — so the
 * effective ceiling on concurrent untrusted workloads is concurrency * replicas.
 */
const logger = createLogger({ name: 'worker' });

async function main(): Promise<void> {
  const config = loadWorkerConfig();
  const connection = createRedisConnection(config.REDIS_URL);
  const producer = new ScanQueueProducer(connection);

  const workers = CONSUMER_QUEUES.map(
    (queueName) =>
      new Worker(
        queueName,
        async (job: Job) => handleJob(queueName, job, producer, config),
        {
          connection,
          prefix: 'syscanner',
          concurrency: config.WORKER_CONCURRENCY,
          // A sandbox that exceeds its deadline must not be retried blindly: each
          // attempt burns a container and the outcome is deterministic.
          lockDuration: config.SANDBOX_TOOL_TIMEOUT_MS + 60_000,
        },
      ),
  );

  for (const worker of workers) {
    worker.on('failed', (job, error) => {
      logger.error(
        { queue: worker.name, jobId: job?.id, attempt: job?.attemptsMade, err: error },
        'job failed',
      );
    });
    worker.on('error', (error) => {
      logger.error({ queue: worker.name, err: error }, 'worker error');
    });
  }

  // Orphan reaper. A worker killed mid-scan leaves two things behind: a container
  // that keeps consuming host resources, and a scratch directory that never gets
  // cleaned up. Both are swept here, on the same timer.
  const reaper = new DockerSandboxProvider();
  const reapInterval = setInterval(
    () => {
      void reaper
        .reap(config.SANDBOX_TOOL_TIMEOUT_MS * 2)
        .then((count) => {
          if (count > 0) logger.warn({ count }, 'reaped orphaned sandboxes');
        })
        .catch((error: unknown) => logger.error({ err: error }, 'sandbox reap failed'));

      void sweepStaleScratch(config, config.SANDBOX_TOOL_TIMEOUT_MS * 2)
        .then((count) => {
          if (count > 0) logger.warn({ count }, 'swept stale scan scratch directories');
        })
        .catch((error: unknown) => logger.error({ err: error }, 'scratch sweep failed'));
    },
    Math.max(config.SANDBOX_TOOL_TIMEOUT_MS, 60_000),
  );

  logger.info(
    { concurrency: config.WORKER_CONCURRENCY, provider: config.SANDBOX_PROVIDER },
    'worker started',
  );

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;

    logger.info({ signal }, 'worker shutting down');
    clearInterval(reapInterval);

    // Close workers first so no new job is claimed, then release shared resources.
    await Promise.allSettled(workers.map((worker) => worker.close()));
    await producer.close();
    await prisma.$disconnect();
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

async function handleJob(
  queueName: string,
  job: Job,
  producer: ScanQueueProducer,
  config: WorkerConfig,
): Promise<void> {
  const log = logger.child({ queue: queueName, jobId: job.id });

  switch (queueName) {
    case QUEUE_NAMES.orchestrate: {
      const payload = parseJobPayload(orchestrateScanJobSchema, job.data, queueName);
      await orchestrateScanJob(payload, producer, config);
      return;
    }
    case QUEUE_NAMES.repository: {
      const payload = parseJobPayload(scanRepositoryJobSchema, job.data, queueName);
      const result = await scanRepositoryJob(payload);
      log.info(
        {
          jobId: result.jobId,
          commitSha: result.commitSha,
          findings: result.findings,
          truncated: result.truncated,
          persisted: result.persisted,
        },
        'repository scan complete',
      );
      return;
    }
    case QUEUE_NAMES.sast:
    case QUEUE_NAMES.secrets:
    case QUEUE_NAMES.dependencies: {
      const payload = parseJobPayload(scannerJobSchema, job.data, queueName);
      await runScannerJob(payload);
      return;
    }
    case QUEUE_NAMES.report: {
      await finalizeScan(job.data?.scanId as string | undefined, log, config);
      return;
    }
    case QUEUE_NAMES.notify: {
      const payload = job.data as Partial<NotifyJob>;
      log.info({ event: payload.event }, 'notification queued (dispatcher not implemented)');
      return;
    }
    default:
      log.warn('no handler registered for queue');
  }
}

/**
 * Marks a scan terminal once every scanner task has settled, then releases the
 * scratch tree.
 *
 * `PARTIAL` is a first-class outcome: one tool failing must not invalidate the
 * findings the others produced, but the customer must be told the result is
 * incomplete rather than presented as clean.
 *
 * This is the correct teardown point. A `finally` inside the orchestrator would
 * delete the source tree while the scanner jobs it just enqueued still need to
 * read it, so ownership of the scratch directory passes here instead.
 */
async function finalizeScan(
  scanId: string | undefined,
  log: { info: (obj: object, msg: string) => void },
  config: WorkerConfig,
): Promise<void> {
  if (!scanId) return;

  const tasks = await prisma.scanTask.findMany({
    where: { scanId },
    select: { status: true },
  });

  if (tasks.length === 0) return;

  const stillRunning = tasks.some((task) => task.status === 'RUNNING' || task.status === 'PENDING');
  if (stillRunning) return;

  const failed = tasks.filter((task) => task.status === 'FAILED' || task.status === 'TIMED_OUT');

  await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: failed.length === 0 ? 'COMPLETED' : 'PARTIAL',
      finishedAt: new Date(),
      errorCode: failed.length > 0 ? 'TASK_FAILED' : null,
      errorMessage:
        failed.length > 0
          ? `${failed.length} of ${tasks.length} scanner tasks did not complete.`
          : null,
    },
  });

  // Every consumer has finished, so the checkout is no longer needed. This runs
  // for both terminal paths (COMPLETED and PARTIAL); a FAILED scan is released by
  // the orchestrator's catch block instead.
  const released = await cleanupScanScratch(config, scanId);

  log.info({ scanId, failedTasks: failed.length, scratchReleased: released }, 'scan finalized');
}

if (require.main === module) {
  main().catch((error: unknown) => {
    logger.error({ err: error }, 'worker failed to start');
    process.exitCode = 1;
  });
}
