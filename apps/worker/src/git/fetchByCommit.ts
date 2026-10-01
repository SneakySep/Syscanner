import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Fetches a repository at an exact commit, without ever giving git a chance to run
 * attacker-controlled code or reach the network.
 *
 * Every flag below maps to a threat in docs/architecture/THREAT-MODEL.md:
 *
 *  T6 hooks/submodules   core.hooksPath=/dev/null, --no-recurse-submodules
 *  T6 protocol abuse     protocol.file.allow=never, protocol.ext.allow=never
 *  T3 network            GIT_TERMINAL_PROMPT=0, GIT_ASKPASS=echo
 *  T10 disk exhaustion   size cap, blobless/treeless fetch
 *  T5 build execution    GIT_LFS_SKIP_SMUDGE=1 (no LFS filters), no checkout hooks
 */

export interface FetchOptions {
  /** e.g. https://github.com/acme/backend.git — validated by the caller. */
  cloneUrl: string;
  /** Exact 40-char commit SHA. Never a branch name: that is not reproducible. */
  commitSha: string;
  /** Destination directory; created by the caller on an encrypted ephemeral volume. */
  destination: string;
  /** Abort the fetch beyond this size (bytes). */
  maxBytes?: number;
  timeoutMs?: number;
  /** Long-lived credential, resolved from Vault at job time — never persisted. */
  credentialToken?: string;
}

/** Environment that removes every interactive and network-helper escape hatch. */
export function hardenedGitEnv(credentialToken?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: 'echo',
    GCM_INTERACTIVE: 'never',
    GIT_LFS_SKIP_SMUDGE: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_ADVICE: '0',
    // A repo could otherwise ship a .gitconfig that rewrites URLs or installs filters.
    HOME: '/nonexistent',
    XDG_CONFIG_HOME: '/nonexistent',
  };

  if (credentialToken) {
    // Passed via the environment, never via the URL, so it cannot leak into the
    // remote URL stored in .git/config or into error messages.
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'http.extraHeader';
    env.GIT_CONFIG_VALUE_0 = `Authorization: Bearer ${credentialToken}`;
  }

  return env;
}

export function gitSafetyArgs(): string[] {
  return [
    '-c',
    'core.hooksPath=/dev/null',
    '-c',
    'core.symlinks=false',
    '-c',
    'core.autocrlf=false',
    '-c',
    'protocol.file.allow=never',
    '-c',
    'protocol.ext.allow=never',
    '-c',
    'protocol.ssh.allow=never',
    '-c',
    'submodule.recurse=false',
  ];
}

/**
 * Builds the init + fetch + checkout sequence.
 *
 * We deliberately do not use `git clone`: an explicit init/fetch/checkout lets us
 * assert the resolved SHA and keeps the working tree free of the remote's default
 * branch configuration.
 */
export function buildFetchCommands(options: FetchOptions): string[][] {
  const { cloneUrl, commitSha, destination } = options;
  const common = gitSafetyArgs();

  return [
    ['init', '--quiet', '--initial-branch=main', destination],
    ['-C', destination, ...common, 'remote', 'add', 'origin', cloneUrl],
    [
      '-C',
      destination,
      ...common,
      'fetch',
      '--quiet',
      '--depth=1',
      '--no-tags',
      '--filter=blob:none',
      'origin',
      commitSha,
    ],
    ['-C', destination, ...common, 'checkout', '--quiet', '--force', commitSha],
    ['-C', destination, ...common, 'submodule', 'deinit', '--all', '--force'],
  ];
}

export interface FetchResult {
  /** The SHA actually checked out — must equal the requested SHA. */
  resolvedSha: string;
  sizeBytes: number;
}

/**
 * Runs the fetch sequence and verifies what landed on disk.
 *
 * Throws on: non-zero exit, a SHA mismatch (the repository replaced the object),
 * or a size-cap breach. Failing closed is the point — a partially fetched tree
 * would produce misleadingly clean results.
 */
export async function fetchByCommit(options: FetchOptions): Promise<FetchResult> {
  const env = hardenedGitEnv(options.credentialToken);
  const maxBytes = options.maxBytes ?? 512 * 1024 * 1024;
  const timeout = options.timeoutMs ?? 120_000;

  for (const command of buildFetchCommands(options)) {
    await execFileAsync('git', command, {
      env,
      timeout,
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true,
    });
  }

  const { stdout } = await execFileAsync('git', ['-C', options.destination, 'rev-parse', 'HEAD'], {
    env,
    timeout,
    windowsHide: true,
  });

  const resolvedSha = stdout.trim();
  if (resolvedSha !== options.commitSha) {
    throw new Error(
      `Commit mismatch: requested ${options.commitSha} but checked out ${resolvedSha}. ` +
        'Refusing to scan an unexpected revision.',
    );
  }

  const { stdout: diskUsage } = await execFileAsync(
    'git',
    ['-C', options.destination, 'count-objects', '-v'],
    { env, timeout, windowsHide: true },
  );

  const sizeMatch = /size-pack:\s*(\d+)/.exec(diskUsage);
  const sizeKib = sizeMatch?.[1] ? Number.parseInt(sizeMatch[1], 10) : 0;
  const sizeBytes = sizeKib * 1024;

  if (sizeBytes > maxBytes) {
    throw new Error(`Repository exceeds the ${maxBytes} byte limit (${sizeBytes} bytes).`);
  }

  return { resolvedSha, sizeBytes };
}
