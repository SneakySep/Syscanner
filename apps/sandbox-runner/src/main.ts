/**
 * Sandbox entrypoint.
 *
 * This process runs INSIDE the sandbox, on a hostile repository's behalf, with no
 * credentials and no network. Assume anything it touches is attacker-controlled.
 *
 * Contract with the orchestrator:
 *   - the job spec arrives on stdin as JSON
 *   - `argv` has already been built by a trusted adapter with hardened flags; this
 *     process executes it verbatim (no shell, no interpolation)
 *   - the SARIF report is written to `reportPath`, which is inside the single
 *     writable mount; nothing else may be written
 *   - the process exits with the tool's exit code
 *
 * Deliberate omissions: no environment inheritance, no shell, no dynamic
 * `--config` from a URL, no reading of the repository's own tool configuration.
 */
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

interface JobSpec {
  /** Absolute path of the executable to run. */
  binary: string;
  /** Exact argument vector, already hardened by the adapter. */
  argv: string[];
  /** Where the SARIF report must be written. */
  reportPath: string;
  /** Unix timestamp (ms) after which the tool must give up. */
  deadlineMs: number;
}

const MAX_SPEC_BYTES = 256 * 1024;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;

  return new Promise<string>((resolve, reject) => {
    process.stdin.on('data', (chunk: Buffer) => {
      total += chunk.length;
      // A job spec is small; anything larger is a bug or an attack.
      if (total > MAX_SPEC_BYTES) {
        reject(new Error('Job spec exceeds the maximum accepted size.'));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function parseSpec(raw: string): JobSpec {
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error('Job spec must be a JSON object.');
  }

  const candidate = parsed as Partial<JobSpec>;
  if (typeof candidate.binary !== 'string' || !candidate.binary.startsWith('/')) {
    throw new Error('Job spec "binary" must be an absolute path.');
  }
  if (!Array.isArray(candidate.argv) || candidate.argv.some((arg) => typeof arg !== 'string')) {
    throw new Error('Job spec "argv" must be an array of strings.');
  }
  if (typeof candidate.reportPath !== 'string' || !candidate.reportPath.startsWith('/')) {
    throw new Error('Job spec "reportPath" must be an absolute path.');
  }

  return {
    binary: candidate.binary,
    argv: candidate.argv,
    reportPath: candidate.reportPath,
    deadlineMs: typeof candidate.deadlineMs === 'number' ? candidate.deadlineMs : Date.now() + 300_000,
  };
}

async function main(): Promise<number> {
  const spec = parseSpec(await readStdin());

  await mkdir(dirname(spec.reportPath), { recursive: true });

  const remainingMs = Math.max(spec.deadlineMs - Date.now(), 1_000);

  return new Promise<number>((resolve) => {
    // `shell: false` is the default and is load-bearing: with a shell, a crafted
    // path or rule id containing shell metacharacters would become command
    // injection inside the sandbox.
    const child = spawn(spec.binary, spec.argv, {
      stdio: ['ignore', 'inherit', 'inherit'],
      shell: false,
      // Inherit nothing: the orchestrator supplies the complete environment.
      env: process.env,
    });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, remainingMs);

    child.on('error', () => {
      clearTimeout(timer);
      resolve(127);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      // Exit codes are passed through, not interpreted: the orchestrator decides
      // whether a non-zero code means "findings found" or "scan failed".
      resolve(code ?? 1);
    });
  });
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(`sandbox-runner: ${(error as Error).message}\n`);
      process.exitCode = 2;
    });
}

export { parseSpec };
