import { TOOL_VERSIONS, triggerScanRequestSchema } from '@syscanner/contracts';
import { computeInputFingerprint, DEFAULT_SCAN_POLICY, parseScanPolicy } from '@syscanner/core';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { requireTenant } from '../tenant';

const paramsSchema = z.object({ repositoryId: z.string().min(1).max(64) });
const scanParamsSchema = z.object({ scanId: z.string().min(1).max(64) });

export async function registerScanRoutes(app: FastifyInstance): Promise<void> {
  /**
   * Trigger a scan.
   *
   * Returns 202 as soon as the scan row exists and the job is queued — the scan
   * itself takes minutes and is streamed to the client over SSE.
   */
  app.post('/v1/repositories/:repositoryId/scans', async (request, reply) => {
    const tenant = requireTenant(request);
    const { repositoryId } = paramsSchema.parse(request.params);
    const body = triggerScanRequestSchema.parse(request.body ?? {});

    // Scoped by organizationId: a cross-tenant id simply resolves to null.
    const repository = await app.prisma.repository.findFirst({
      where: { id: repositoryId, organizationId: tenant.organizationId, deletedAt: null },
      select: { id: true, defaultBranch: true, scanConfig: true },
    });

    if (!repository) {
      return reply.code(404).send({
        error: { code: 'REPOSITORY_NOT_FOUND', message: 'Repository not found.' },
      });
    }

    // Resolving a branch tip to a commit SHA requires an SCM round-trip. That
    // resolver is intentionally not implemented here: the webhook path always
    // supplies a SHA, and the branch-resolution integration is a separate seam.
    if (!body.commitSha) {
      return reply.code(400).send({
        error: {
          code: 'COMMIT_SHA_REQUIRED',
          message:
            'An explicit commitSha is required until branch-tip resolution is wired to the SCM client.',
        },
      });
    }

    const policy = parseScanPolicy(repository.scanConfig ?? DEFAULT_SCAN_POLICY);
    const policyVersion = 1;
    const enabledTools = Object.fromEntries(
      Object.entries(TOOL_VERSIONS).filter(([tool]) => isToolEnabled(policy, tool)),
    );

    const inputFingerprint = computeInputFingerprint({
      repositoryId: repository.id,
      commitSha: body.commitSha,
      policyVersion,
      toolVersions: enabledTools,
    });

    // Idempotent: re-requesting the same commit under the same policy reuses the row.
    const scan = await app.prisma.scan.upsert({
      where: {
        repositoryId_commitSha_inputFingerprint: {
          repositoryId: repository.id,
          commitSha: body.commitSha,
          inputFingerprint,
        },
      },
      update: {},
      create: {
        organizationId: tenant.organizationId,
        repositoryId: repository.id,
        triggeredById: tenant.userId ?? null,
        branch: body.branch ?? repository.defaultBranch,
        commitSha: body.commitSha,
        prNumber: body.prNumber ?? null,
        inputFingerprint,
        policyVersion,
        toolVersions: enabledTools,
      },
      select: { id: true, status: true, commitSha: true, createdAt: true },
    });

    await app.queues.enqueueScan({
      scanId: scan.id,
      organizationId: tenant.organizationId,
      repositoryId: repository.id,
      commitSha: body.commitSha,
      manual: true,
    });

    await app.prisma.auditLog.create({
      data: {
        organizationId: tenant.organizationId,
        actorId: tenant.userId ?? null,
        action: 'scan.created',
        targetType: 'scan',
        targetId: scan.id,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] ?? null,
        metadata: { repositoryId: repository.id, commitSha: body.commitSha },
      },
    });

    return reply.code(202).send({
      id: scan.id,
      status: scan.status,
      commitSha: scan.commitSha,
      createdAt: scan.createdAt.toISOString(),
    });
  });

  /** Scan summary, including the denormalized severity rollup. */
  app.get('/v1/scans/:scanId', async (request, reply) => {
    const tenant = requireTenant(request);
    const { scanId } = scanParamsSchema.parse(request.params);

    const scan = await app.prisma.scan.findFirst({
      where: { id: scanId, organizationId: tenant.organizationId },
      include: { repository: { select: { fullName: true } }, tasks: true },
    });

    if (!scan) {
      return reply.code(404).send({ error: { code: 'SCAN_NOT_FOUND', message: 'Scan not found.' } });
    }

    return {
      id: scan.id,
      repositoryId: scan.repositoryId,
      repositoryFullName: scan.repository.fullName,
      status: scan.status,
      branch: scan.branch,
      commitSha: scan.commitSha,
      totalFindings: scan.totalFindings,
      criticalCount: scan.criticalCount,
      highCount: scan.highCount,
      mediumCount: scan.mediumCount,
      lowCount: scan.lowCount,
      infoCount: scan.infoCount,
      durationMs: scan.durationMs,
      startedAt: scan.startedAt?.toISOString() ?? null,
      finishedAt: scan.finishedAt?.toISOString() ?? null,
      createdAt: scan.createdAt.toISOString(),
      tasks: scan.tasks.map((task) => ({
        id: task.id,
        kind: task.kind,
        tool: task.tool,
        status: task.status,
        durationMs: task.durationMs,
      })),
    };
  });
}

/** Maps a policy's enabled scanner kinds onto the tools that implement them. */
function isToolEnabled(
  policy: { scanners: readonly string[] },
  tool: string,
): boolean {
  const toolToKind: Record<string, string> = {
    semgrep: 'SAST',
    gitleaks: 'SECRETS',
    'osv-scanner': 'DEPENDENCY',
    trivy: 'LICENSE',
  };
  const kind = toolToKind[tool];
  return kind === undefined || policy.scanners.includes(kind);
}
