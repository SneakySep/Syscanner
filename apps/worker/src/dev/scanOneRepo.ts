/**
 * ⚠ DEVELOPMENT USE ONLY — NOT THE PRODUCTION PATH ⚠
 *
 * A deliberately unsafe single-repository scanner: shallow `git clone` on the host
 * followed by `semgrep scan --config=auto --json`, with the temp directory torn down
 * in a `finally`. It exists for local debugging when Docker (and therefore the real
 * sandbox) is unavailable.
 *
 * It returns the same normalized shape the production path does, so findings can be
 * eyeballed or piped into a fixture.
 *
 * THE PRODUCTION PATH IS: apps/worker/src/processors/scanRepository.ts
 *   - SHA-pinned fetch by an explicit commit (not a moving branch tip)
 *   - execution inside gVisor/Kata with no network, no credentials, and cgroup caps
 *   - an image-bundled ruleset instead of `--config=auto`
 *
 * This file must never be wired into a queue or called from a request handler.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { resolveSeverity } from '@syscanner/core';

import { gitSafetyArgs, hardenedGitEnv } from '../git/fetchByCommit';
import { assertSafeCloneUrl } from '../git/validateCloneUrl';
// Type-only import: erased at compile time, so this script never loads the Prisma
// client and therefore never needs a DATABASE_URL.
import type { FindingRow } from '../ingest';

const CLONE_TIMEOUT_MS = 120_000;
const SEMGREP_TIMEOUT_MS = 300_000;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

const execFileAsync = promisify(execFile);

interface CommandOutcome {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Runs a command without a shell.
 *
 * A shell is never used: the repository URL is attacker-influenced, so a shell
 * would turn a crafted value into command injection. `allowNonZero` exists because
 * Semgrep exits 1 whenever it finds issues, which is a *successful* scan for us.
 *
 * NOTE: `execa` was the original choice here, but execa v9 ships as ESM-only and
 * this monorepo compiles to CommonJS, so it cannot be `require`d. Using the Node
 * built-in keeps the project's module system unchanged and drops a dependency.
 */
async function run(
  file: string,
  args: readonly string[],
  options: { env?: NodeJS.ProcessEnv; timeout: number; allowNonZero?: boolean },
): Promise<CommandOutcome> {
  try {
    const { stdout, stderr } = await execFileAsync(file, [...args], {
      env: options.env ?? process.env,
      timeout: options.timeout,
      maxBuffer: MAX_OUTPUT_BYTES,
      windowsHide: true,
    });

    return { stdout: String(stdout), stderr: String(stderr), exitCode: 0 };
  } catch (error) {
    if (options.allowNonZero !== true) throw error;

    const shaped = error as {
      stdout?: string | Buffer;
      stderr?: string | Buffer;
      code?: number | string;
      killed?: boolean;
    };

    return {
      stdout: shaped.stdout === undefined ? '' : String(shaped.stdout),
      stderr: shaped.stderr === undefined ? '' : String(shaped.stderr),
      exitCode: typeof shaped.code === 'number' ? shaped.code : 1,
    };
  }
}

const WARNING = `
╔══════════════════════════════════════════════════════════════════════════════╗
║  SAFETY CONTROLS ARE OFF — DEVELOPMENT USE ONLY                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This script deliberately violates the Syscanner threat model:                ║
║                                                                              ║
║   T1   Nothing is sandboxed. Semgrep parses attacker-authored files in this   ║
║        process, on this host. A parser bug is a full machine compromise.      ║
║   T3   The clone and the scanner run with your network access and your        ║
║        environment, so any credential in the process env is reachable.        ║
║   T11  --config=auto fetches rules from the Semgrep Registry at scan time.    ║
║        There is no offline mode and results are not reproducible: the same    ║
║        commit can produce different findings tomorrow.                         ║
║                                                                              ║
║  Mitigated anyway (free wins, not a substitute for the sandbox):              ║
║   • hooks, submodules and LFS smudge filters are disabled via the git env     ║
║   • Semgrep telemetry is off (--metrics=off)                                  ║
║   • the clone URL is validated only-as-https by the production validator      ║
║                                                                              ║
║  For a real scan use: apps/worker/src/processors/scanRepository.ts            ║
╚══════════════════════════════════════════════════════════════════════════════╝
`;

interface CliOptions {
  url: string;
  branch?: string;
  out?: string;
  acknowledged: boolean;
}

const USAGE =
  'Usage: pnpm --filter @syscanner/worker run dev:scan-one -- <repository-url> ' +
  '--i-understand-this-is-not-sandboxed [--branch <name>] [--out <file>]';

function parseArgs(argv: readonly string[]): CliOptions {
  const values: Record<string, string> = {};
  let url: string | undefined;
  let acknowledged = false;

  const takeValue = (index: number, flag: string): string => {
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('-')) {
      throw new Error(`${flag} requires a value.`);
    }
    return next;
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === undefined) continue;

    if (arg === '--i-understand-this-is-not-sandboxed') {
      acknowledged = true;
    } else if (arg === '--branch') {
      values.branch = takeValue(index, '--branch');
      index += 1;
    } else if (arg === '--out') {
      values.out = takeValue(index, '--out');
      index += 1;
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown argument: ${arg}\n${USAGE}`);
    } else if (url === undefined) {
      url = arg;
    } else {
      throw new Error(`Unexpected extra argument: ${arg}\n${USAGE}`);
    }
  }

  if (url === undefined) {
    throw new Error(`A repository URL is required.\n${USAGE}`);
  }

  return {
    url,
    ...(values.branch === undefined ? {} : { branch: values.branch }),
    ...(values.out === undefined ? {} : { out: values.out }),
    acknowledged,
  };
}

/** Semgrep's JSON severity vocabulary, mapped onto ours. */
const SEMGREP_SEVERITY: Record<string, 'HIGH' | 'MEDIUM' | 'LOW'> = {
  ERROR: 'HIGH',
  WARNING: 'MEDIUM',
  INFO: 'LOW',
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

/**
 * Maps one Semgrep `--json` result onto the columns of a `Finding` row.
 *
 * The return type comes from the production mapper (`FindingRow`), so a change to
 * the database shape breaks this script at compile time rather than silently
 * producing a payload the database would reject.
 */
function toPayload(result: Record<string, unknown>, scanner = 'semgrep'): FindingRow | undefined {
  const ruleId = asString(result.check_id);
  // A result with no rule id cannot be fingerprinted or triaged; drop it.
  if (ruleId === undefined) return undefined;

  const extra = asRecord(result.extra) ?? {};
  const metadata = asRecord(extra.metadata) ?? {};
  const start = asRecord(result.start) ?? {};
  const end = asRecord(result.end) ?? {};

  const message = asString(extra.message) ?? ruleId;
  const level = asString(extra.severity)?.toUpperCase();
  const toolSeverity = level === undefined ? undefined : SEMGREP_SEVERITY[level];

  const rawSecuritySeverity = metadata['security-severity'];
  const cvss =
    typeof rawSecuritySeverity === 'number'
      ? rawSecuritySeverity
      : typeof rawSecuritySeverity === 'string'
        ? Number.parseFloat(rawSecuritySeverity)
        : undefined;
  const hasCvss = cvss !== undefined && Number.isFinite(cvss);

  const filePath = asString(result.path);
  const lines = asString(extra.lines);

  return {
    kind: 'SAST',
    scanner,
    ruleId,
    title: message.length > 512 ? message.slice(0, 512) : message,
    description: null,
    category: asString(metadata.category) ?? null,
    references: asStringArray(metadata.references),
    severity: resolveSeverity(toolSeverity, hasCvss ? cvss : undefined),
    cvssScore: hasCvss ? String(cvss) : null,
    cvssVector: asString(metadata.cvssVector) ?? null,
    cweIds: [...new Set(asStringArray(metadata.cwe).map((value) => value.toUpperCase()))],
    cveIds: [],
    ghsaId: null,
    owaspCategory: asStringArray(metadata.owasp).join(', ') || null,
    filePath: filePath === undefined ? null : filePath.replace(/\\/g, '/').replace(/^\.\//, ''),
    startLine: asNumber(start.line) ?? null,
    endLine: asNumber(end.line) ?? null,
    startColumn: asNumber(start.col) ?? null,
    endColumn: asNumber(end.col) ?? null,
    // As in production only the hash is kept: `extra.lines` can contain a live secret.
    snippetHash:
      lines === undefined ? null : createHash('sha256').update(lines, 'utf8').digest('hex'),
    packageName: null,
    packageVersion: null,
    fixedVersion: null,
    ecosystem: null,
    dependencyPath: null,
  };
}

function safeJson(text: string): Record<string, unknown> | undefined {
  try {
    return asRecord(JSON.parse(text));
  } catch {
    return undefined;
  }
}

async function main(): Promise<number> {
  const options = parseArgs(process.argv.slice(2));

  // Two gates, because this script is easy to invoke by accident from CI.
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'Refusing to run: this script is not sandboxed and must never run in production.',
    );
  }

  if (!options.acknowledged) {
    process.stderr.write(WARNING);
    process.stderr.write(`\nRe-run with --i-understand-this-is-not-sandboxed.\n${USAGE}\n`);
    return 2;
  }

  process.stderr.write(WARNING);

  // Validated even here: protocol abuse, flag injection and SSRF cost nothing to
  // refuse, and a developer machine has credentials worth stealing too.
  const url = assertSafeCloneUrl(options.url);

  const workDir = await mkdtemp(join(tmpdir(), 'syscanner-devscan-'));
  const cloneDir = join(workDir, 'repo');

  try {
    process.stderr.write(`Cloning ${url}\n`);
    await run(
      'git',
      [
        // Reused from the production fetch path: no hooks, no file:/ext: protocols.
        // Combined with hardenedGitEnv this disables LFS smudge filters as well.
        ...gitSafetyArgs(),
        'clone',
        '--depth',
        '1',
        '--no-tags',
        '--single-branch',
        '--no-recurse-submodules',
        ...(options.branch === undefined ? [] : ['--branch', options.branch]),
        url,
        cloneDir,
      ],
      { env: { ...process.env, ...hardenedGitEnv() }, timeout: CLONE_TIMEOUT_MS },
    );

    const { stdout: head } = await run('git', ['-C', cloneDir, 'rev-parse', 'HEAD'], {
      env: { ...process.env, ...hardenedGitEnv() },
      timeout: CLONE_TIMEOUT_MS,
    });
    const commitSha = head.trim();
    process.stderr.write(`Resolved commit: ${commitSha}\n`);

    // `--config=auto` requires network access to resolve its ruleset; that is the
    // T11 violation called out above. `--metrics=off` is kept because telemetry
    // leaks nothing useful and costs nothing to disable.
    // `reject: false` because Semgrep exits 1 whenever it finds issues.
    const semgrep = await run(
      'semgrep',
      [
        'scan',
        '--config=auto',
        '--json',
        '--metrics=off',
        '--disable-version-check',
        '--quiet',
        cloneDir,
      ],
      { timeout: SEMGREP_TIMEOUT_MS, allowNonZero: true },
    );

    const parsed = safeJson(semgrep.stdout);
    if (parsed === undefined) {
      process.stderr.write(
        `Semgrep produced no parseable JSON (exit ${String(semgrep.exitCode)}). ` +
          'Is `semgrep` installed and on PATH?\n' +
          `${semgrep.stderr.slice(0, 2_000)}\n`,
      );
      return 1;
    }

    const results = Array.isArray(parsed.results) ? parsed.results : [];
    const payloads = results
      .map((result) => asRecord(result))
      .filter((result): result is Record<string, unknown> => result !== undefined)
      .map((result) => toPayload(result))
      .filter((payload): payload is FindingRow => payload !== undefined);

    const report = {
      mode: 'dev-unsandboxed',
      note: 'Produced by the dev script, not by a sandboxed scan. See scanRepository.ts.',
      repositoryUrl: url,
      commitSha,
      branch: options.branch ?? '(default branch tip)',
      scanner: 'semgrep',
      scannerConfig: 'auto (fetched from the Semgrep Registry)',
      findings: payloads.length,
      payloads,
    };

    const serialized = `${JSON.stringify(report, null, 2)}\n`;

    if (options.out === undefined) {
      process.stdout.write(serialized);
    } else {
      await writeFile(options.out, serialized, 'utf8');
      process.stderr.write(`Wrote ${String(payloads.length)} findings to ${options.out}\n`);
    }

    return 0;
  } finally {
    // Runs on success, on throw, and when Semgrep is not installed at all. The temp
    // tree never survives this call — which is exactly the guarantee the production
    // processor also makes.
    await rm(workDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(`dev:scan-one failed: ${(error as Error).message}\n`);
      process.exitCode = 1;
    });
}

export { main, parseArgs, toPayload };

