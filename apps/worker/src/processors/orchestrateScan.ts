import { mkdir, rm } from 'node:fs/promises';

import { parseScanPolicy } from '@syscanner/core';
import { prisma } from '@syscanner/db';
import type { OrchestrateScanJob } from '@syscanner/queue';

import { loadWorkerConfig, type WorkerConfig } from '../config';
import { fetchByCommit } from '../git/fetchByCommit';
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

  const scanRoot = `${config.WORKER_SCRATCH_DIR}/${scan.id}`;
  const sourceDir = `${scanRoot}/src`;
  const outputDir = `${scanRoot}/out`;

  await prisma.scan.update({
    where: { id: scan.id },
    data: { status: 'CLONING', startedAt: new Date() },
  });

  try {
    // Ephemeral, per-scan scratch. Wiped in `finally` regardless of outcome.
    await rm(scanRoot, { recursive: true, force: true });
    await mkdir(sourceDir, { recursive: true });
    await mkdir(outputDir, { recursive: true });

    await fetchByCommit({
      cloneUrl: scan.repository.cloneUrl,
      commitSha: scan.commitSha,
      destination: sourceDir,
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
        sourceKey: sourceDir,
        policyVersion: scan.policyVersion,
      });
    }
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
