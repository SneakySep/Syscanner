import { parseScanPolicy } from '@syscanner/core';
import { prisma } from '@syscanner/db';
import type { OrchestrateScanJob } from '@syscanner/queue';

import { loadWorkerConfig, type WorkerConfig } from '../config';
import { fetchByCommit } from '../git/fetchByCommit';
import { cleanupScanScratch, prepareScanScratch } from '../scratch';
import type { ScanQueueProducer } from '@syscanner/queue';

/**
 * Phase 1 of a scan: fetch the source, then fan out one job per enabled scanner.
 *
 * Splitting fetch from scanning is what allows a slow SAST pass and a fast secrets
 * pass to run independently, and lets a single tool fail without discarding the
 * others' results.
 */
export async function orchestrateScanJob(
  job: OrchestrateScanJob,
  producer: ScanQueueProducer,
  config: WorkerConfig = loadWorkerConfig(),
): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: job.scanId },
    select: {
      id: true,
      status: true,
      commitSha: true,
      policyVersion: true,
      organizationId: true,
      repositoryId: true,
      repository: {
        select: { cloneUrl: true, isPrivate: true, scanConfig: true },
      },
    },
  });

  if (!scan) {
    throw new Error(`Scan ${job.scanId} does not exist.`);
  }

  // Idempotency guard: a redelivered job must not restart a scan that is already
  // running or finished. The status transition is the compare-and-swap.
  if (scan.status !== 'QUEUED') {
    return;
  }

  await prisma.scan.update({
    where: { id: scan.id },
    data: { status: 'CLONING', startedAt: new Date() },
  });

  try {
    // A fresh, empty tree. `prepareScanScratch` wipes any leftover from a previous
    // attempt, so a retry never inherits a half-fetched checkout.
    const scratch = await prepareScanScratch(config, scan.id);

    await fetchByCommit({
      cloneUrl: scan.repository.cloneUrl,
      commitSha: scan.commitSha,
      destination: scratch.sourceDir,
      maxBytes: config.SANDBOX_MAX_REPO_MB * 1024 * 1024,
      timeoutMs: config.SANDBOX_CLONE_TIMEOUT_MS,
      // Resolved from Vault/KMS at job time by the caller in production; never
      // persisted alongside the repository row.
      credentialToken: undefined,
    });

    const policy = parseScanPolicy(scan.repository.scanConfig);

    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: 'SCANNING' },
    });

    for (const kind of policy.scanners) {
      const tool = TOOL_FOR_KIND[kind];
      if (!tool) continue;

      await producer.enqueueScanner({
        scanId: scan.id,
        organizationId: scan.organizationId,
        repositoryId: scan.repositoryId,
        kind,
        tool,
        commitSha: scan.commitSha,
        sourceKey: scratch.sourceDir,
        policyVersion: scan.policyVersion,
      });
    }

    // The scratch tree is deliberately NOT removed here: the scanner jobs
    // enqueued above still need to read it. Ownership passes to `finalizeScan`,
    // which runs once every ScanTask has settled. See apps/worker/src/index.ts.
  } catch (error) {
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: 'FAILED',
        finishedAt: new Date(),
        errorCode: 'FETCH_FAILED',
        errorMessage: error instanceof Error ? error.message : 'Unknown fetch failure',
      },
    });

    // The tree is unusable now, so release the disk immediately rather than
    // waiting for the stale-directory sweeper.
    await cleanupScanScratch(config, scan.id);
    throw error;
  }
}

const TOOL_FOR_KIND: Record<string, string | undefined> = {
  SAST: 'semgrep',
  SECRETS: 'gitleaks',
  DEPENDENCY: 'osv-scanner',
  LICENSE: 'trivy',
};

export type { ScanQueueProducer };
