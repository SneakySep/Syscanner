import { z } from 'zod';

/**
 * Wire contracts shared by `apps/web`, `apps/api` and `apps/worker`.
 *
 * These schemas are the single source of truth for request/response shapes: the
 * API validates inbound bodies against them and the web app infers its types from
 * them, so the two can never drift.
 */

export const severitySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']);

export const findingStatusSchema = z.enum([
  'OPEN',
  'RESOLVED',
  'IGNORED',
  'FALSE_POSITIVE',
  'WONT_FIX',
]);

export const scannerKindSchema = z.enum([
  'SAST',
  'SECRETS',
  'DEPENDENCY',
  'LICENSE',
  'IAC',
  'CONTAINER',
  'SBOM',
]);

export const scanStatusSchema = z.enum([
  'QUEUED',
  'CLONING',
  'SCANNING',
  'PARSING',
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'CANCELLED',
]);

export const scmProviderSchema = z.enum([
  'GITHUB',
  'GITLAB',
  'BITBUCKET',
  'AZURE_DEVOPS',
  'GENERIC_GIT',
]);

// ── Requests ─────────────────────────────────────────────────────────────────

export const createRepositoryRequestSchema = z.object({
  provider: scmProviderSchema,
  providerRepoId: z.string().min(1).max(128),
  fullName: z.string().min(3).max(256),
  cloneUrl: z.string().url().max(1024),
  defaultBranch: z.string().min(1).max(255).default('main'),
  isPrivate: z.boolean().default(true),
  /** Reference into Vault/KMS. A raw token must never appear in a request body. */
  credentialRef: z.string().max(512).optional(),
});
export type CreateRepositoryRequest = z.infer<typeof createRepositoryRequestSchema>;

export const triggerScanRequestSchema = z.object({
  commitSha: z
    .string()
    .regex(/^[0-9a-f]{7,64}$/i)
    .optional(),
  branch: z.string().min(1).max(255).optional(),
  prNumber: z.number().int().positive().optional(),
});
export type TriggerScanRequest = z.infer<typeof triggerScanRequestSchema>;

export const updateFindingRequestSchema = z.object({
  status: findingStatusSchema,
  reason: z.string().min(3).max(2000).optional(),
});
export type UpdateFindingRequest = z.infer<typeof updateFindingRequestSchema>;

export const listFindingsQuerySchema = z.object({
  severity: severitySchema.optional(),
  status: findingStatusSchema.optional(),
  kind: scannerKindSchema.optional(),
  cveId: z.string().max(64).optional(),
  filePath: z.string().max(1024).optional(),
  repositoryId: z.string().max(64).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().max(128).optional(),
});
export type ListFindingsQuery = z.infer<typeof listFindingsQuerySchema>;

// ── Responses ────────────────────────────────────────────────────────────────

export const scanSummarySchema = z.object({
  id: z.string(),
  repositoryId: z.string(),
  repositoryFullName: z.string(),
  status: scanStatusSchema,
  branch: z.string().nullable(),
  commitSha: z.string(),
  totalFindings: z.number().int(),
  criticalCount: z.number().int(),
  highCount: z.number().int(),
  mediumCount: z.number().int(),
  lowCount: z.number().int(),
  infoCount: z.number().int(),
  durationMs: z.number().int().nullable(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  createdAt: z.string(),
});
export type ScanSummary = z.infer<typeof scanSummarySchema>;

export const findingSchema = z.object({
  id: z.string(),
  fingerprint: z.string(),
  scanId: z.string(),
  repositoryId: z.string(),
  kind: scannerKindSchema,
  scanner: z.string(),
  ruleId: z.string(),
  title: z.string(),
  description: z.string().nullable(),
  severity: severitySchema,
  cvssScore: z.number().nullable(),
  cweIds: z.array(z.string()),
  cveIds: z.array(z.string()),
  ghsaId: z.string().nullable(),
  status: findingStatusSchema,
  filePath: z.string().nullable(),
  startLine: z.number().int().nullable(),
  endLine: z.number().int().nullable(),
  packageName: z.string().nullable(),
  packageVersion: z.string().nullable(),
  fixedVersion: z.string().nullable(),
  ecosystem: z.string().nullable(),
  detectedAt: z.string(),
});
export type Finding = z.infer<typeof findingSchema>;

export const scanProgressEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('status'),
    scanId: z.string(),
    status: scanStatusSchema,
    at: z.string(),
  }),
  z.object({
    type: z.literal('task'),
    scanId: z.string(),
    taskId: z.string(),
    tool: z.string(),
    status: z.string(),
    at: z.string(),
  }),
  z.object({
    type: z.literal('done'),
    scanId: z.string(),
    totalFindings: z.number().int(),
    at: z.string(),
  }),
]);
export type ScanProgressEvent = z.infer<typeof scanProgressEventSchema>;

export const errorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    requestId: z.string().optional(),
  }),
});
export type ErrorResponse = z.infer<typeof errorResponseSchema>;

// ── Scanner toolchain ────────────────────────────────────────────────────────

/**
 * Canonical pinned versions of every scanner tool.
 *
 * These live in `contracts` rather than in `scanners` on purpose: the API computes
 * a scan's idempotency fingerprint from them, while `scanners` is sandbox-only code
 * that the API is forbidden to import (see ARCHITECTURE.md §2.1). Keeping one
 * definition means the fingerprint and the sandbox can never disagree.
 */
export const TOOL_NAMES = ['semgrep', 'gitleaks', 'osv-scanner', 'trivy'] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

export const TOOL_VERSIONS: Record<ToolName, string> = {
  semgrep: '1.90.0',
  gitleaks: '8.21.2',
  'osv-scanner': '1.9.0',
  trivy: '0.55.0',
};
