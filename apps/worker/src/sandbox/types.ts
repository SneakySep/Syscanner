/**
 * Sandbox provider contract.
 *
 * The orchestrator programs against this interface rather than against Docker, so
 * the isolation tier is a deployment decision rather than a code change. A
 * gVisor/Kata/Firecracker implementation only has to honour these guarantees:
 *
 *  - the workload runs in a throwaway instance that is destroyed afterwards
 *  - CPU, memory, PID and wall-clock limits are enforced by the *host*, so the
 *    workload cannot opt out of them
 *  - the source tree is readable but not writable
 *  - only `outputDir` is writable, and it is the single outbound channel
 *  - the workload receives exactly `spec.env` and nothing else
 *  - no inbound connectivity, and egress only if explicitly configured
 */

export interface SandboxLimits {
  cpus: number;
  memoryMb: number;
  pidsLimit: number;
  tmpfsMb: number;
  /** Hard deadline. The orchestrator kills the whole cgroup on expiry. */
  timeoutMs: number;
  /** "none" is the only acceptable default for untrusted repositories. */
  network: 'none' | 'allowlist-proxy';
  /** Container runtime class, e.g. "runsc" for gVisor. */
  runtimeClass?: string;
  /** Path to the seccomp profile enforced on the workload. */
  seccompProfilePath?: string;
}

export interface SandboxSpec {
  /** Digest-pinned image reference. Tags are rejected. */
  image: string;
  /** argv executed inside the sandbox. Never a shell string. */
  argv: string[];
  env: Record<string, string>;
  /** Read-only mount: the fetched source tree. */
  sourceDir: string;
  /** Read-write mount: the only place the sandbox may write. */
  outputDir: string;
  /** Working directory inside the sandbox. */
  workDir: string;
  limits: SandboxLimits;
  /** Correlates host-level telemetry (cgroup stats, SIEM alerts) with a scan. */
  labels: Record<string, string>;
}

export interface SandboxResult {
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
  /** Bytes the workload attempted to send outside its sandbox. Must be 0. */
  egressBytes: number;
}

export interface SandboxProvider {
  readonly name: string;
  run(spec: SandboxSpec): Promise<SandboxResult>;
  /** Reaps orphaned sandboxes left behind by a crashed worker. */
  reap(olderThanMs: number): Promise<number>;
}

/**
 * A digest-pinned image reference. Refusing tags here is a supply-chain control:
 * `:latest` can be repointed by whoever controls the registry.
 */
export function assertDigestPinned(image: string): void {
  if (!image.includes('@sha256:') || !/sha256:[0-9a-f]{64}$/i.test(image)) {
    throw new Error(
      `Sandbox image must be digest-pinned (got "${image}"). Use registry/image@sha256:<64 hex>.`,
    );
  }
}

/**
 * Guards against argument injection: rejects NUL bytes and newlines that could be
 * used to smuggle extra arguments through a wrapper.
 */
export function assertSafeArgv(argv: readonly string[]): void {
  for (const argument of argv) {
    if (/[\u0000\n\r]/.test(argument)) {
      throw new Error(`Unsafe control character in sandbox argv: ${JSON.stringify(argument)}`);
    }
  }
}
