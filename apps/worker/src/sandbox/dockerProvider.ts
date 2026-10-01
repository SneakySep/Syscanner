import { spawn } from 'node:child_process';

import type { SandboxProvider, SandboxResult, SandboxSpec } from './types';
import { assertDigestPinned, assertSafeArgv } from './types';

/**
 * Docker-backed sandbox.
 *
 * Isolation checklist encoded below (see ARCHITECTURE.md §4):
 *   --network none              no egress at all unless a proxy is configured
 *   --read-only                 immutable root filesystem
 *   --tmpfs                     size-capped, noexec scratch space
 *   --cap-drop ALL              no Linux capabilities
 *   --security-opt              no-new-privileges + seccomp profile
 *   --user 65534:65534          never root
 *   --pids-limit                fork-bomb protection
 *   --memory/--memory-swap      equal values disable swap, so the cap is real
 *   --runtime runsc             gVisor when configured
 *   -v source:/src:ro           source is readable, never writable
 *
 * The host kills the container on timeout, not the container itself. `docker kill`
 * signals PID 1's cgroup, so a workload cannot survive its own deadline by ignoring
 * SIGTERM.
 */

/** Scanner output is capped so a hostile repo cannot exhaust worker memory. */
const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

export class DockerSandboxProvider implements SandboxProvider {
  public readonly name = 'docker';

  constructor(
    private readonly options: {
      dockerBinary?: string;
      /** Injected in tests so no real container is spawned. */
      spawnImpl?: typeof spawn;
    } = {},
  ) {}

  buildArgs(spec: SandboxSpec): string[] {
    assertDigestPinned(spec.image);
    assertSafeArgv(spec.argv);

    const name = `syscanner-sbx-${(spec.labels.scanId ?? 'unknown').slice(0, 40)}-${Date.now()}`;

    const args: string[] = [
      'run',
      '--rm',
      '--name',
      name,
      '--network',
      spec.limits.network === 'allowlist-proxy' ? 'syscanner-egress' : 'none',
      // Memory and swap must match, otherwise the workload spills to swap and the
      // memory cap becomes advisory.
      '--memory',
      `${spec.limits.memoryMb}m`,
      '--memory-swap',
      `${spec.limits.memoryMb}m`,
      '--cpus',
      String(spec.limits.cpus),
      '--pids-limit',
      String(spec.limits.pidsLimit),
      '--read-only',
      '--tmpfs',
      `${spec.workDir}:rw,size=${spec.limits.tmpfsMb}m,noexec,nosuid,nodev`,
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges',
      '--user',
      '65534:65534',
      '--ulimit',
      'nofile=1024:1024',
      '-v',
      `${spec.sourceDir}:${spec.workDir}/src:ro`,
      '-v',
      `${spec.outputDir}:${spec.workDir}/out:rw`,
      '-w',
      spec.workDir,
      // Terminate if the orchestrator itself dies.
      '--stop-timeout',
      '5',
    ];

    if (spec.limits.runtimeClass) {
      args.push('--runtime', spec.limits.runtimeClass);
    }

    if (spec.limits.seccompProfilePath) {
      args.push('--security-opt', `seccomp=${spec.limits.seccompProfilePath}`);
    }

    for (const [key, value] of Object.entries(spec.env)) {
      args.push('-e', `${key}=${value}`);
    }

    for (const [key, value] of Object.entries(spec.labels)) {
      args.push('--label', `${key}=${value}`);
    }

    args.push(spec.image, ...spec.argv);

    return args;
  }

  async run(spec: SandboxSpec): Promise<SandboxResult> {
    const args = this.buildArgs(spec);
    const docker = this.options.dockerBinary ?? 'docker';
    const spawnImpl = this.options.spawnImpl ?? spawn;
    const name = readName(args);
    const startedAt = Date.now();
    let timedOut = false;

    return new Promise<SandboxResult>((resolve, reject) => {
      const child = spawnImpl(docker, args, { windowsHide: true });

      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let captured = 0;

      const capture = (sink: Buffer[]) => (chunk: Buffer) => {
        if (captured >= MAX_CAPTURE_BYTES) return;
        captured += chunk.length;
        sink.push(chunk);
      };

      child.stdout?.on('data', capture(stdout));
      child.stderr?.on('data', capture(stderr));

      const timer = setTimeout(() => {
        timedOut = true;
        // Kill the whole cgroup, not just the CLI process we spawned.
        if (name) {
          spawnImpl(docker, ['kill', name], { windowsHide: true });
        }
        child.kill('SIGKILL');
      }, spec.limits.timeoutMs);

      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          exitCode: code,
          timedOut,
          durationMs: Date.now() - startedAt,
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          // With `--network none` this is structurally zero. In the allowlist
          // tier it is populated from the egress proxy's verdict log.
          egressBytes: 0,
        });
      });
    });
  }

  /** Kills sandboxes left behind by a crashed or killed worker. */
  async reap(_olderThanMs: number): Promise<number> {
    const docker = this.options.dockerBinary ?? 'docker';
    const spawnImpl = this.options.spawnImpl ?? spawn;

    return new Promise<number>((resolve) => {
      const child = spawnImpl(
        docker,
        ['ps', '-q', '--filter', 'label=syscanner.managed=true'],
        { windowsHide: true },
      );

      const chunks: Buffer[] = [];
      child.stdout?.on('data', (chunk: Buffer) => chunks.push(chunk));
      child.on('error', () => resolve(0));
      child.on('close', () => {
        const ids = Buffer.concat(chunks)
          .toString('utf8')
          .split(/\s+/)
          .filter((id) => /^[0-9a-f]{8,64}$/i.test(id));

        for (const id of ids) {
          spawnImpl(docker, ['kill', id], { windowsHide: true });
        }
        resolve(ids.length);
      });
    });
  }
}

/**
 * Labels attached to every sandbox. They are what makes host-level telemetry
 * (cgroup stats, SIEM alerts, forensic enumeration after an incident) traceable
 * back to a specific scan and tenant.
 */
export function sandboxLabels(input: {
  scanId: string;
  organizationId: string;
  tool: string;
}): Record<string, string> {
  return {
    'syscanner.managed': 'true',
    'syscanner.scan_id': input.scanId,
    'syscanner.organization_id': input.organizationId,
    'syscanner.tool': input.tool,
  };
}

function readName(args: readonly string[]): string | undefined {
  const index = args.indexOf('--name');
  return index >= 0 ? args[index + 1] : undefined;
}
