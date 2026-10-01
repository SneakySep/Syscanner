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
