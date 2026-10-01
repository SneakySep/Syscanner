import { z } from 'zod';

/**
 * Worker configuration, including every sandbox limit.
 *
 * Limits are configuration rather than code so they can be tuned per environment,
 * but they are validated at boot: a worker that cannot prove its sandbox is
 * correctly constrained must not start.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.string().default('info'),

  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1).default('redis://localhost:6379'),

  WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(64).default(4),

  // ── Sandbox ──
  SANDBOX_PROVIDER: z.enum(['docker', 'gvisor', 'kata', 'firecracker']).default('docker'),
  /** Container runtime class, e.g. "runsc". Required for the gVisor tier. */
  SANDBOX_RUNTIME: z.string().optional(),
  SANDBOX_IMAGE: z.string().default('syscanner/sandbox-runner'),
  SANDBOX_IMAGE_SAST: z.string().optional(),
  SANDBOX_IMAGE_SECRETS: z.string().optional(),
  SANDBOX_IMAGE_DEPS: z.string().optional(),
  SANDBOX_CPUS: z.coerce.number().positive().default(1.5),
  SANDBOX_MEMORY_MB: z.coerce.number().int().positive().default(2048),
  SANDBOX_PIDS_LIMIT: z.coerce.number().int().positive().default(256),
  SANDBOX_TMPFS_MB: z.coerce.number().int().positive().default(2048),
  /** "none" unless an allowlist egress proxy is deployed. */
  SANDBOX_NETWORK: z.enum(['none', 'allowlist-proxy']).default('none'),
  SANDBOX_SECCOMP_PROFILE: z.string().optional(),

  SANDBOX_CLONE_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
  SANDBOX_TOOL_TIMEOUT_MS: z.coerce.number().int().positive().default(300_000),
  SANDBOX_MAX_REPO_MB: z.coerce.number().int().positive().default(512),
  /** Hard cap on findings per scan — protects the control plane from a noisy repo. */
  SANDBOX_MAX_FINDINGS: z.coerce.number().int().positive().default(10_000),

  /** Root directory on the worker host for ephemeral checkouts. */
  WORKER_SCRATCH_DIR: z.string().default('/work/syscanner'),
});

export type WorkerConfig = z.infer<typeof envSchema>;

let cached: WorkerConfig | undefined;

export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): WorkerConfig {
  if (cached) return cached;

  const result = envSchema.safeParse(env);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '<root>'}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid worker configuration:\n${details}`);
  }

  // Fail closed: the gVisor tier is meaningless without the runtime class.
  if (result.data.SANDBOX_PROVIDER === 'gvisor' && !result.data.SANDBOX_RUNTIME) {
    throw new Error('SANDBOX_RUNTIME (e.g. "runsc") is required when SANDBOX_PROVIDER=gvisor');
  }

  cached = result.data;
  return cached;
}

export function sandboxImageFor(config: WorkerConfig, kind: string): string {
  if (kind === 'SAST') return config.SANDBOX_IMAGE_SAST ?? config.SANDBOX_IMAGE;
  if (kind === 'SECRETS') return config.SANDBOX_IMAGE_SECRETS ?? config.SANDBOX_IMAGE;
  return config.SANDBOX_IMAGE_DEPS ?? config.SANDBOX_IMAGE;
}
