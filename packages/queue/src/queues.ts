/**
 * Queue topology.
 *
 * Every stage of a scan is a separate queue so that a slow or failing stage cannot
 * block the others, and so concurrency can be tuned per stage (SAST is CPU-heavy,
 * notification dispatch is I/O-bound).
 */
export const QUEUE_NAMES = {
  /** API -> orchestrator: "plan and run this scan". */
  orchestrate: 'scan:orchestrate',
  /** Orchestrator -> SAST sandbox. */
  sast: 'scan:sast',
  /** Orchestrator -> secrets-detection sandbox. */
  secrets: 'scan:secrets',
  /** Orchestrator -> dependency/SCA sandbox. */
  dependencies: 'scan:deps',
  /** Collect per-tool results, dedupe, write aggregates. */
  report: 'scan:report',
  /** Outbound notifications (Slack, email, GitHub checks). */
  notify: 'notify:dispatch',
  /** Jobs that exhausted their attempts. Never auto-retried. */
  deadLetter: 'scan:dead-letter',
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

/** Queues that a worker process consumes. */
export const CONSUMER_QUEUES: readonly QueueName[] = [
  QUEUE_NAMES.orchestrate,
  QUEUE_NAMES.sast,
  QUEUE_NAMES.secrets,
  QUEUE_NAMES.dependencies,
  QUEUE_NAMES.report,
  QUEUE_NAMES.notify,
] as const;

export const SCANNER_QUEUE_BY_KIND = {
  SAST: QUEUE_NAMES.sast,
  SECRETS: QUEUE_NAMES.secrets,
  DEPENDENCY: QUEUE_NAMES.dependencies,
  LICENSE: QUEUE_NAMES.dependencies,
} as const;

/**
 * Retention policy. Completed jobs are dropped quickly (they carry scan metadata),
 * failed jobs are kept longer for forensics.
 */
export const DEFAULT_JOB_OPTIONS = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 5_000 },
  removeOnComplete: { age: 3_600, count: 1_000 },
  removeOnFail: { age: 86_400, count: 5_000 },
} as const;

/**
 * A scanner job is never retried blindly: a hostile repository will fail the same
 * way every time, and each attempt costs a sandbox. Retries are therefore limited
 * and only apply to infrastructure faults, which the processor distinguishes.
 */
export const SCANNER_JOB_OPTIONS = {
  ...DEFAULT_JOB_OPTIONS,
  attempts: 2,
} as const;
