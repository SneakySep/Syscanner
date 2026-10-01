import { TOOL_NAMES as TOOL_NAMES_CONTRACT, TOOL_VERSIONS } from '@syscanner/contracts';
import type { FindingKindName } from '@syscanner/core';

/**
 * Tool adapters.
 *
 * These functions do not execute anything. They describe *exactly* how a tool must
 * be invoked inside the sandbox, with the hardened flags baked in so a caller
 * cannot forget them. The sandbox runner executes the returned argv verbatim.
 *
 * Hardening rules encoded here:
 *  1. Rule/config files are always read from the image-bundled trusted path —
 *     never from a URL, never from the repository.
 *  2. Telemetry, version checks and auto-updates are off: a scan must not depend on
 *     network egress, and must not phone home with customer data.
 *  3. Secrets are redacted by the tool itself (`--redact`) in addition to our own
 *     redaction, so raw credentials never reach the artifact.
 *  4. Output is always SARIF to a fixed path, so the parser contract is uniform.
 */

export const TOOL_NAMES = TOOL_NAMES_CONTRACT;
export type ToolName = (typeof TOOL_NAMES)[number];

/** Re-exported so the sandbox and the API share one pinned toolchain. */
export const PINNED_TOOL_VERSIONS: Record<ToolName, string> = TOOL_VERSIONS;

export interface ScanTarget {
  /** Absolute path to the read-only checkout inside the sandbox. */
  sourceDir: string;
  /** Absolute path the tool must write its SARIF report to. */
  reportPath: string;
  /** Path of the trusted ruleset bundled in the sandbox image. */
  trustedConfigPath?: string;
  /** Repo paths to skip. Validated by the caller; passed as literal argv values. */
  excludePaths?: string[];
  timeoutSeconds?: number;
  maxMemoryMb?: number;
}

export interface ToolInvocation {
  tool: ToolName;
  version: string;
  /** argv passed to execve — no shell, therefore no shell-injection surface. */
  argv: string[];
  /** The complete environment the sandbox exposes. Nothing else is inherited. */
  env: Record<string, string>;
}

/**
 * The only environment variables a scanner ever sees.
 *
 * Note what is absent: DATABASE_URL, REDIS_URL, SCM tokens, KMS keys, proxy
 * credentials. There is deliberately no `...process.env` spread anywhere.
 */
export const HARDENED_SCANNER_ENV: Record<string, string> = {
  PATH: '/usr/local/bin:/usr/bin:/bin',
  HOME: '/work',
  TMPDIR: '/work/tmp',
  CI: 'true',
  NO_COLOR: '1',
  // Semgrep telemetry and self-update must both be off: no egress, no data leaving.
  SEMGREP_SEND_METRICS: 'off',
  SEMGREP_ENABLE_VERSION_CHECK: '0',
  GITLEAKS_ENABLE_UPLOAD_ARTIFACT: 'false',
  // Trivy must never try to refresh its vulnerability DB mid-scan.
  TRIVY_SKIP_DB_UPDATE: 'true',
  TRIVY_SKIP_JAVA_DB_UPDATE: 'true',
  TRIVY_NO_PROGRESS: 'true',
};

const DEFAULT_TIMEOUT_SECONDS = 300;
const DEFAULT_MAX_MEMORY_MB = 1536;

function excludeArgs(paths: readonly string[] | undefined): string[] {
  return (paths ?? []).flatMap((path) => ['--exclude', path]);
}

/** SAST via Semgrep, using only the trusted bundled ruleset. */
export function buildSemgrepInvocation(target: ScanTarget): ToolInvocation {
  const configPath = target.trustedConfigPath ?? '/opt/syscanner/rules/semgrep';

  return {
    tool: 'semgrep',
    version: PINNED_TOOL_VERSIONS.semgrep,
    argv: [
      'semgrep',
      'scan',
      // Local path only. A remote `--config https://...` would let repository
      // content influence what code executes.
      '--config',
      configPath,
      '--sarif',
      '--output',
      target.reportPath,
      '--metrics=off',
      '--disable-version-check',
      '--no-rewrite-rule-ids',
      '--quiet',
      '--jobs',
      '1',
      '--timeout',
      String(target.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS),
      '--max-memory',
      String(target.maxMemoryMb ?? DEFAULT_MAX_MEMORY_MB),
      ...excludeArgs(target.excludePaths),
      target.sourceDir,
    ],
    env: HARDENED_SCANNER_ENV,
  };
}

/** Secrets detection via Gitleaks, told to redact matches itself. */
export function buildGitleaksInvocation(target: ScanTarget): ToolInvocation {
  const configPath = target.trustedConfigPath;

  return {
    tool: 'gitleaks',
    version: PINNED_TOOL_VERSIONS.gitleaks,
    argv: [
      'gitleaks',
      'detect',
      '--source',
      target.sourceDir,
      // We asked git for an archive, not a clone: there is no history to walk.
      '--no-git',
      '--report-format',
      'sarif',
      '--report-path',
      target.reportPath,
      // Never emit the matched secret value, only its location.
      '--redact',
      '--no-banner',
      '--exit-code',
      '0',
      ...(configPath ? ['--config', configPath] : []),
    ],
    env: HARDENED_SCANNER_ENV,
  };
}

/**
 * Dependency / SCA scanning via osv-scanner.
 *
 * `--offline` is essential: it scans the lockfiles we already have instead of
 * resolving or downloading anything, which is why this tool can run with no
 * network access at all.
 */
export function buildOsvScannerInvocation(target: ScanTarget): ToolInvocation {
  return {
    tool: 'osv-scanner',
    version: PINNED_TOOL_VERSIONS['osv-scanner'],
    argv: [
      'osv-scanner',
      'scan',
      'source',
      '--format',
      'sarif',
      '--output',
      target.reportPath,
      '--offline',
      '--recursive',
      '--no-ignore',
      ...excludeArgs(target.excludePaths),
      target.sourceDir,
    ],
    env: HARDENED_SCANNER_ENV,
  };
}

/** License policy scanning via Trivy in filesystem mode. */
export function buildTrivyInvocation(target: ScanTarget): ToolInvocation {
  return {
    tool: 'trivy',
    version: PINNED_TOOL_VERSIONS.trivy,
    argv: [
      'trivy',
      'fs',
      '--format',
      'sarif',
      '--output',
      target.reportPath,
      '--scanners',
      'license',
      '--skip-db-update',
      '--offline-scan',
      '--no-progress',
      ...excludeArgs(target.excludePaths),
      target.sourceDir,
    ],
    env: HARDENED_SCANNER_ENV,
  };
}

export interface ScannerDescriptor {
  kind: FindingKindName;
  tool: ToolName;
  build: (target: ScanTarget) => ToolInvocation;
}

/**
 * The registry the orchestrator fans out over. `kind` maps to a queue through
 * `SCANNER_QUEUE_BY_KIND` in @syscanner/queue.
 */
export const SCANNER_REGISTRY: readonly ScannerDescriptor[] = [
  { kind: 'SAST', tool: 'semgrep', build: buildSemgrepInvocation },
  { kind: 'SECRETS', tool: 'gitleaks', build: buildGitleaksInvocation },
  { kind: 'DEPENDENCY', tool: 'osv-scanner', build: buildOsvScannerInvocation },
  { kind: 'LICENSE', tool: 'trivy', build: buildTrivyInvocation },
] as const;

export function descriptorFor(kind: FindingKindName): ScannerDescriptor | undefined {
  return SCANNER_REGISTRY.find((descriptor) => descriptor.kind === kind);
}
