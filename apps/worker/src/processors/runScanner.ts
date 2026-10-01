import { parseScanPolicy } from '@syscanner/core';
import { prisma } from '@syscanner/db';
import type { ScannerJob } from '@syscanner/queue';
import { descriptorFor, PINNED_TOOL_VERSIONS } from '@syscanner/scanners';

import { loadWorkerConfig, sandboxImageFor, type WorkerConfig } from '../config';
import { ingestFindings } from '../ingest';
import { scanScratchPaths } from '../scratch';
import { DockerSandboxProvider, sandboxLabels } from '../sandbox/dockerProvider';
import type { SandboxProvider } from '../sandbox/types';
import { executeSandboxedTool } from './executeSandboxedTool';

/**
 * Runs one scanner against one already-fetched source tree.
 *
 * The pipeline is deliberately narrow:
 *   build argv (hardened) -> run sandbox -> read SARIF -> validate -> ingest
 *
 * Nothing from inside the sandbox is trusted: the only thing we take out of it is
 * a JSON artifact, and even that is size-capped, schema-checked and sanitized.
 */
export async function runScannerJob(
  job: ScannerJob,
  dependencies: { provider?: SandboxProvider; config?: WorkerConfig } = {},
): Promise<void> {
  const config = dependencies.config ?? loadWorkerConfig();
  const provider = dependencies.provider ?? new DockerSandboxProvider();

  const descriptor = descriptorFor(job.kind);
  if (!descriptor) {
    throw new Error(`No scanner descriptor registered for kind ${job.kind}`);
  }

  const scan = await prisma.scan.findUnique({
    where: { id: job.scanId },
    select: {
      id: true,
      organizationId: true,
      repositoryId: true,
      toolVersions: true,
      repository: { select: { scanConfig: true } },
    },
  });

  if (!scan) {
    throw new Error(`Scan ${job.scanId} no longer exists; dropping scanner job.`);
  }

  const policy = parseScanPolicy(scan.repository.scanConfig);
  const { sourceDir, outputDir } = scanScratchPaths(config, job.scanId);
  const reportPath = `${outputDir}/${descriptor.tool}.sarif`;

  const task = await prisma.scanTask.upsert({
    where: { scanId_kind_tool: { scanId: job.scanId, kind: job.kind, tool: descriptor.tool } },
    update: {
      status: 'RUNNING',
      startedAt: new Date(),
      attempt: { increment: 1 },
    },
    create: {
      scanId: job.scanId,
      kind: job.kind,
      tool: descriptor.tool,
      // Recorded per task so a result can always be traced back to the exact tool
      // build that produced it.
      toolVersion: PINNED_TOOL_VERSIONS[descriptor.tool],
      status: 'RUNNING',
      startedAt: new Date(),
      attempt: 1,
    },
    select: { id: true },
  });

  const invocation = descriptor.build({
    sourceDir,
    reportPath,
    // Trusted, image-bundled ruleset. Repo-supplied configs are never used.
    trustedConfigPath:
      descriptor.tool === 'semgrep' ? '/opt/syscanner/rules/semgrep' : undefined,
    excludePaths: policy.excludePaths,
  });

  const outcome = await executeSandboxedTool({
    tool: descriptor.tool,
    kind: job.kind,
    argv: invocation.argv,
    env: invocation.env,
    image: sandboxImageFor(config, job.kind),
    sourceDir,
    outputDir,
    reportPath,
    maxFindings: config.SANDBOX_MAX_FINDINGS,
    labels: sandboxLabels({
      scanId: job.scanId,
      organizationId: job.organizationId,
      tool: descriptor.tool,
    }),
    config,
    provider,
  });

  // A scanner must never be able to reach the network. If it did, this is a
  // containment failure and the scan is marked as such rather than silently trusted.
  if (outcome.containmentViolation) {
    await prisma.scanTask.update({
      where: { id: task.id },
      data: {
        status: 'FAILED',
        finishedAt: new Date(),
        durationMs: outcome.durationMs,
        errorMessage: `Containment violation: ${outcome.egressBytes} bytes of egress observed.`,
      },
    });
    throw new Error('Sandbox containment violation: network egress detected.');
  }

  if (outcome.timedOut) {
    await prisma.scanTask.update({
      where: { id: task.id },
      data: {
        status: 'TIMED_OUT',
        timedOut: true,
        finishedAt: new Date(),
        durationMs: outcome.durationMs,
        errorMessage: `Timed out after ${config.SANDBOX_TOOL_TIMEOUT_MS} ms.`,
      },
    });
    return;
  }

  await ingestFindings(
    {
      scanId: scan.id,
      organizationId: scan.organizationId,
      repositoryId: scan.repositoryId,
      taskId: task.id,
      maxFindings: config.SANDBOX_MAX_FINDINGS,
    },
    outcome.findings,
  );

  await prisma.scanTask.update({
    where: { id: task.id },
    data: {
      status: 'SUCCEEDED',
      exitCode: outcome.exitCode,
      finishedAt: new Date(),
      durationMs: outcome.durationMs,
      resultArtifactKey: reportPath,
      errorMessage: outcome.warnings.length > 0 ? outcome.warnings.join(' | ') : null,
    },
  });
}
