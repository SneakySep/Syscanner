import { z } from 'zod';

/**
 * Every job payload crossing the Redis boundary is validated with zod.
 *
 * Redis must be treated as an untrusted transport: a compromised or shared Redis
 * instance must not be able to inject arbitrary objects into a worker.
 */

export const scannerKindSchema = z.enum([
  'SAST',
  'SECRETS',
  'DEPENDENCY',
  'LICENSE',
  'IAC',
  'CONTAINER',
  'SBOM',
]);

export const commitShaSchema = z
  .string()
  .regex(/^[0-9a-f]{7,64}$/i, 'commitSha must be a hex git object id');

const ids = {
  scanId: z.string().min(1).max(64),
  organizationId: z.string().min(1).max(64),
  repositoryId: z.string().min(1).max(64),
};

export const orchestrateScanJobSchema = z.object({
  ...ids,
  commitSha: commitShaSchema,
  /** True when a human asked for this scan (audit trail / rate-limit exemption). */
  manual: z.boolean().default(false),
});
export type OrchestrateScanJob = z.infer<typeof orchestrateScanJobSchema>;
/**
 * Callers of the producer pass the *input* type: fields with zod defaults
 * (`manual`, `policyVersion`) are optional at the call site but always present
 * once `parseJobPayload` has run.
 */
export type OrchestrateScanJobInput = z.input<typeof orchestrateScanJobSchema>;

export const scannerJobSchema = z.object({
  ...ids,
  kind: scannerKindSchema,
  /** The tool to run inside the sandbox, e.g. "semgrep". */
  tool: z.string().min(1).max(64),
  commitSha: commitShaSchema,
  /** Key of the read-only source tree the orchestrator prepared. */
  sourceKey: z.string().min(1).max(512),
  policyVersion: z.number().int().positive().default(1),
});
export type ScannerJob = z.infer<typeof scannerJobSchema>;
export type ScannerJobInput = z.input<typeof scannerJobSchema>;

/**
 * A self-contained "scan this repository URL" job.
 *
 * `orchestrateScanJob` references a `Scan` row the API already created; this job
 * instead carries its own inputs, so it can be submitted from a CLI, a webhook or
 * an external integration without a prior database write.
 */
export const scanRepositoryJobSchema = z.object({
  /**
   * Caller-supplied correlation id, also used as the BullMQ job id.
   *
   * The character class is narrow on purpose: this value becomes a directory name
   * under the worker's scratch root, so permitting `:` or a path separator here
   * would hand an attacker control of the cleanup path.
   */
  jobId: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,64}$/, 'jobId must be 1-64 characters of [A-Za-z0-9_-]'),
  /** Validated again by `assertSafeCloneUrl` before it reaches git. */
  repositoryUrl: z.string().min(1).max(2_048),
  /** Exact commit to scan. A branch name is refused: a moving tip is not reproducible. */
  commitSha: commitShaSchema,
  /** Human-readable ref, recorded for display only. */
  ref: z.string().max(256).optional(),
  /** Present when the job is attached to an existing tenant and repository. */
  organizationId: z.string().min(1).max(64).optional(),
  repositoryId: z.string().min(1).max(64).optional(),
  /**
   * Ruleset location. Defaults to the image-bundled trusted path. A remote URL is
   * never accepted — see ARCHITECTURE.md §4.3.
   */
  semgrepConfigPath: z.string().max(512).optional(),
});
export type ScanRepositoryJob = z.infer<typeof scanRepositoryJobSchema>;
export type ScanRepositoryJobInput = z.input<typeof scanRepositoryJobSchema>;

export const aggregateReportJobSchema = z.object({
  ...ids,
  commitSha: commitShaSchema,
});
export type AggregateReportJob = z.infer<typeof aggregateReportJobSchema>;
export type AggregateReportJobInput = z.input<typeof aggregateReportJobSchema>;

export const notifyJobSchema = z.object({
  ...ids,
  scanId: z.string().min(1).max(64),
  event: z.enum(['scan.completed', 'scan.failed', 'finding.critical']),
});
export type NotifyJob = z.infer<typeof notifyJobSchema>;
export type NotifyJobInput = z.input<typeof notifyJobSchema>;

/**
 * Parses a job payload, returning the schema's *output* type.
 *
 * Typing the generic as `z.ZodTypeAny` and returning `z.output<T>` matters: with a
 * bare `z.ZodType<T>`, TypeScript has to satisfy `T` in both the output and input
 * positions, and for schemas containing `.default()` it silently infers the input
 * type instead — so callers would receive `{ manual?: boolean }` where the processor
 * requires `{ manual: boolean }`.
 */
export function parseJobPayload<T extends z.ZodTypeAny>(
  schema: T,
  payload: unknown,
  queueName: string,
): z.output<T> {
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new Error(
      `Invalid ${queueName} job payload: ${result.error.issues
        .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ')}`,
    );
  }
  return result.data as z.output<T>;
}
