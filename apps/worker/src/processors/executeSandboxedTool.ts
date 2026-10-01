import { readFile } from 'node:fs/promises';

import type { FindingKindName } from '@syscanner/core';
import { parseSarif, type NormalizedFinding } from '@syscanner/scanners';

import type { WorkerConfig } from '../config';
import type { SandboxProvider } from '../sandbox/types';

/**
 * Runs one scanner inside the sandbox and returns its normalized findings.
 *
 * Everything from inside the container is untrusted: the only thing taken out is a
 * JSON artifact, and even that is size-capped, schema-tolerated and sanitized by
 * the parser. This function is deliberately free of database access, which makes it
 * reusable by any processor and straightforward to exercise with a fake provider.
 */

export interface ExecuteSandboxedToolInput {
  tool: string;
  kind: FindingKindName;
  argv: string[];
  env: Record<string, string>;
  image: string;
  sourceDir: string;
  outputDir: string;
  reportPath: string;
  labels: Record<string, string>;
  maxFindings: number;
  config: WorkerConfig;
  provider: SandboxProvider;
}

export interface SandboxedToolOutcome {
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  egressBytes: number;
  /** True when the workload reached the network: its output must not be trusted. */
  containmentViolation: boolean;
  truncated: boolean;
  findings: NormalizedFinding[];
  warnings: string[];
  reportPath: string;
}

export async function executeSandboxedTool(
  input: ExecuteSandboxedToolInput,
): Promise<SandboxedToolOutcome> {
  const result = await input.provider.run({
    image: input.image,
    argv: input.argv,
    env: input.env,
    sourceDir: input.sourceDir,
    outputDir: input.outputDir,
    workDir: '/work',
    limits: {
      cpus: input.config.SANDBOX_CPUS,
      memoryMb: input.config.SANDBOX_MEMORY_MB,
      pidsLimit: input.config.SANDBOX_PIDS_LIMIT,
      tmpfsMb: input.config.SANDBOX_TMPFS_MB,
      timeoutMs: input.config.SANDBOX_TOOL_TIMEOUT_MS,
      network: input.config.SANDBOX_NETWORK,
      runtimeClass: input.config.SANDBOX_RUNTIME,
      seccompProfilePath: input.config.SANDBOX_SECCOMP_PROFILE,
    },
    labels: input.labels,
  });

  const base = {
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    timedOut: result.timedOut,
    egressBytes: result.egressBytes,
    reportPath: input.reportPath,
  };

  if (result.egressBytes > 0) {
    return {
      ...base,
      containmentViolation: true,
      truncated: false,
      findings: [],
      warnings: ['The workload reached the network; its results were discarded.'],
    };
  }

  if (result.timedOut) {
    return {
      ...base,
      containmentViolation: false,
      truncated: false,
      findings: [],
      warnings: ['The workload exceeded its deadline; its results were discarded.'],
    };
  }

  const report = await readReport(input.reportPath);
  if (!report) {
    return {
      ...base,
      containmentViolation: false,
      truncated: false,
      findings: [],
      warnings: ['No SARIF report was produced.'],
    };
  }

  // Exit code 1 from a scanner usually just means "findings were reported", so the
  // report — not the exit code — is the source of truth.
  const parsed = parseSarif(report, {
    scanner: input.tool,
    kind: input.kind,
    maxResults: input.maxFindings,
  });

  return {
    ...base,
    containmentViolation: false,
    truncated: parsed.truncated,
    findings: parsed.findings,
    warnings: parsed.warnings,
  };
}

async function readReport(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
}
