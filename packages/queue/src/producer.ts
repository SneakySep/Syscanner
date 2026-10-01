import { Queue, type JobsOptions } from 'bullmq';
import type { Redis } from 'ioredis';

import { createRedisConnection } from './connection';
import {
  DEFAULT_JOB_OPTIONS,
  QUEUE_NAMES,
  SCANNER_JOB_OPTIONS,
  SCANNER_QUEUE_BY_KIND,
  type QueueName,
} from './queues';
import type {
  AggregateReportJobInput,
  NotifyJobInput,
  OrchestrateScanJobInput,
  ScannerJobInput,
} from './jobs';

/**
 * Producer side of the scan pipeline. The API service is the only caller, so all
 * scan scheduling is funnelled through one place (easy to audit, rate-limit, meter).
 */
export class ScanQueueProducer {
  private readonly queues = new Map<QueueName, Queue>();

  constructor(private readonly connection: Redis = createRedisConnection()) {}

  private queue(name: QueueName): Queue {
    let existing = this.queues.get(name);
    if (!existing) {
      existing = new Queue(name, { connection: this.connection, prefix: 'syscanner' });
      this.queues.set(name, existing);
    }
    return existing;
  }

  /** `scanId` is the BullMQ job id, so re-enqueueing the same scan is a no-op. */
  async enqueueScan(job: OrchestrateScanJobInput): Promise<string> {
    const added = await this.queue(QUEUE_NAMES.orchestrate).add('orchestrate', job, {
      ...DEFAULT_JOB_OPTIONS,
      jobId: `orchestrate:${job.scanId}`,
    } as JobsOptions);
    return added.id ?? job.scanId;
  }

  async enqueueScanner(job: ScannerJobInput): Promise<string> {
    const queueName = SCANNER_QUEUE_BY_KIND[job.kind as keyof typeof SCANNER_QUEUE_BY_KIND];
    const target = queueName ?? QUEUE_NAMES.sast;

    const added = await this.queue(target).add(job.tool, job, {
      ...SCANNER_JOB_OPTIONS,
      jobId: `${job.tool}:${job.scanId}`,
    } as JobsOptions);
    return added.id ?? job.scanId;
  }

  async enqueueReport(job: AggregateReportJobInput): Promise<string> {
    const added = await this.queue(QUEUE_NAMES.report).add('aggregate', job, {
      ...DEFAULT_JOB_OPTIONS,
      jobId: `report:${job.scanId}`,
    } as JobsOptions);
    return added.id ?? job.scanId;
  }

  async enqueueNotification(job: NotifyJobInput): Promise<string> {
    const added = await this.queue(QUEUE_NAMES.notify).add(job.event, job, {
      ...DEFAULT_JOB_OPTIONS,
      attempts: 5,
    } as JobsOptions);
    return added.id ?? `${job.event}:${job.scanId}`;
  }

  async close(): Promise<void> {
    await Promise.all([...this.queues.values()].map((queue) => queue.close()));
    this.queues.clear();
    await this.connection.quit();
  }
}

export { createRedisConnection };
