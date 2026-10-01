import { TOOL_VERSIONS } from '@syscanner/contracts';
import { computeInputFingerprint } from '@syscanner/core';
import { prisma } from '@syscanner/db';
import type { ScanRepositoryJob } from '@syscanner/queue';
import { buildSemgrepInvocation, type NormalizedFinding } from '@syscanner/scanners';

import { loadWorkerConfig, sandboxImageFor, type WorkerConfig } from '../config';
import { fetchByCommit } from '../git/fetchByCommit';
import { assertSafeCloneUrl } from '../git/validateCloneUrl';
import { ingestFindings, toDatabasePayload, type FindingRow } from '../ingest';
import { cleanupScanScratch, prepareScanScratch } from '../scratch';
import { DockerSandboxProvider, sandboxLabels } from '../sandbox/dockerProvider';
import type { SandboxProvider } from '../sandbox/types';
import { executeSandboxedTool } from './executeSandboxedTool';

/**
 * `scan_repository` — a self-contained "scan this repository" job.
 *
 * Pipeline, in order:
 *   1. validate the URL        (flag injection, protocol abuse, SSRF)
 *   2. fetch the exact commit  (hooks/submodules/LFS disabled, SHA verified)
 *   3. run Semgrep in a sandbox (trusted bundled ruleset, no network)
 *   4. format findings          into structured database payloads
 *   5. persist                  only when attached to a tenant
 *   6. destroy the checkout     in `finally`, on every path
 *
 * Step 6 is the point worth calling out: this processor owns the whole lifecycle of
 * its checkout, so a `finally` is exactly right. (Contrast `orchestrateScanJob`,
 * which cannot delete its tree because the scanner jobs it spawns still need it —
 * that cleanup happens in `finalizeScan` instead.)
 *
 * And step 3 is where this deliberately diverges from a naive implementation: the
 * scan does not run on the worker host, and it does not use `--config=auto`.
 */

const SEMGREP_TOOL = 'semgrep';
/** Image-bundled ruleset. A repository can never supply or influence this path. */
const TRUSTED_RULESET_PATH = '/opt/syscanner/rules/semgrep';

export interface ScanRepositoryDependencies {
  provider?: SandboxProvider;
  config?: WorkerConfig;
}

export interface RepositoryScanResult {
  jobId: string;
  commitSha: string;
  scanner: string;
  scanId?: string;
  persisted: boolean;
  findings: number;
  truncated: boolean;
  warnings: string[];
  durationMs: number;
  /** Every finding as a database row, returned even when nothing was persisted. */
  payloads: FindingRow[];
}

export async function scanRepositoryJob(
  job: ScanRepositoryJob,
  dependencies: ScanRepositoryDependencies = {},
): Promise<RepositoryScanResult> {
  const config = dependencies.config ?? loadWorkerConfig();
  const provider = dependencies.provider ?? new DockerSandboxProvider();

  // 1. Validate before anything touches git or the filesystem.
  const repositoryUrl = assertSafeCloneUrl(job.repositoryUrl);

  const scratch = await prepareScanScratch(config, job.jobId);
  const reportPath = `${scratch.outputDir}/${SEMGREP_TOOL}.sarif`;

  try {
    // 2. Fetch exactly the requested commit. `fetchByCommit` also asserts that the
    //    checked-out SHA matches, so rewritten history cannot swap the revision.
    await fetchByCommit({
      cloneUrl: repositoryUrl,
      commitSha: job.commitSha,
      destination: scratch.sourceDir,
      maxBytes: config.SANDBOX_MAX_REPO_MB * 1024 * 1024,
      timeoutMs: config.SANDBOX_CLONE_TIMEOUT_MS,
    });

    // 3. Execute Semgrep inside the sandbox against the trusted bundled ruleset.
    const invocation = buildSemgrepInvocation({
      sourceDir: scratch.sourceDir,
      reportPath,
      trustedConfigPath: job.semgrepConfigPath ?? TRUSTED_RULESET_PATH,
    });

    const outcome = await executeSandboxedTool({
      tool: SEMGREP_TOOL,
      kind: 'SAST',
      argv: invocation.argv,
      env: invocation.env,
      image: sandboxImageFor(config, 'SAST'),
      sourceDir: scratch.sourceDir,
      outputDir: scratch.outputDir,
      reportPath,
      maxFindings: config.SANDBOX_MAX_FINDINGS,
      labels: sandboxLabels({
        scanId: job.jobId,
        organizationId: job.organizationId ?? 'standalone',
        tool: SEMGREP_TOOL,
      }),
      config,
      provider,
    });

    if (outcome.containmentViolation) {
      throw new Error(
        `Containment violation: ${outcome.egressBytes} bytes of egress observed; results discarded.`,
      );
    }

    // 4. Format the findings into structured database payloads.
    const accepted = outcome.findings.slice(0, config.SANDBOX_MAX_FINDINGS);
    const payloads = accepted.map(toDatabasePayload);

    // 5. Persist only when the job is attached to a tenant. A standalone job
    //    returns its payloads instead, so a CLI caller decides what to do with them.
    let persisted = false;
    let scanId: string | undefined;

    if (job.organizationId && job.repositoryId) {
      scanId = await persistRepositoryScan({
        job,
        organizationId: job.organizationId,
        repositoryId: job.repositoryId,
        findings: accepted,
        maxFindings: config.SANDBOX_MAX_FINDINGS,
      });
      persisted = true;
    }

    return {
      jobId: job.jobId,
      commitSha: job.commitSha,
      scanner: SEMGREP_TOOL,
      ...(scanId === undefined ? {} : { scanId }),
      persisted,
      findings: payloads.length,
      truncated: outcome.truncated,
      warnings: outcome.warnings,
      durationMs: outcome.durationMs,
      payloads,
    };
  } finally {
    // Runs on success, on throw, and on any early return. This is the cleanup the
    // job contract promises, and it is now actually enforced.
    await cleanupScanScratch(config, job.jobId);
  }
}

/**
 * Persists the result of an attached repository scan.
 *
 * Kept separate from `scanRepositoryJob` so the scanning path stays readable and so
 * the database shape of a standalone scan is obvious in one place: upsert the
 * `Scan` (idempotent on the commit + policy fingerprint), upsert its `ScanTask`,
 * ingest the findings, then mark both terminal.
 */
async function persistRepositoryScan(input: {
  job: ScanRepositoryJob;
  organizationId: string;
  repositoryId: string;
  findings: readonly NormalizedFinding[];
  maxFindings: number;
}): Promise<string> {
  const toolVersions = { [SEMGREP_TOOL]: TOOL_VERSIONS.semgrep };

  const inputFingerprint = computeInputFingerprint({
    repositoryId: input.repositoryId,
    commitSha: input.job.commitSha,
    policyVersion: 1,
    toolVersions,
  });

  const scan = await prisma.scan.upsert({
    where: {
      repositoryId_commitSha_inputFingerprint: {
        repositoryId: input.repositoryId,
        commitSha: input.job.commitSha,
        inputFingerprint,
      },
    },
    update: { status: 'SCANNING' },
    create: {
      organizationId: input.organizationId,
      repositoryId: input.repositoryId,
      trigger: 'API',
      status: 'SCANNING',
      branch: input.job.ref ?? null,
      commitSha: input.job.commitSha,
      inputFingerprint,
      policyVersion: 1,
      toolVersions,
    },
    select: { id: true },
  });

  const task = await prisma.scanTask.upsert({
    where: { scanId_kind_tool: { scanId: scan.id, kind: 'SAST', tool: SEMGREP_TOOL } },
    update: { status: 'RUNNING', startedAt: new Date(), attempt: { increment: 1 } },
    create: {
      scanId: scan.id,
      kind: 'SAST',
      tool: SEMGREP_TOOL,
      toolVersion: TOOL_VERSIONS.semgrep,
      status: 'RUNNING',
      startedAt: new Date(),
      attempt: 1,
    },
    select: { id: true },
  });

  await ingestFindings(
    {
      scanId: scan.id,
      organizationId: input.organizationId,
      repositoryId: input.repositoryId,
      taskId: task.id,
      maxFindings: input.maxFindings,
    },
    input.findings,
  );

  await prisma.scanTask.update({
    where: { id: task.id },
    data: { status: 'SUCCEEDED', finishedAt: new Date() },
  });

  await prisma.scan.update({
    where: { id: scan.id },
    data: { status: 'COMPLETED', finishedAt: new Date() },
  });

  return scan.id;
}
