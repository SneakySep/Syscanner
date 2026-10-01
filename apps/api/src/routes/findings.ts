import { listFindingsQuerySchema, updateFindingRequestSchema } from '@syscanner/contracts';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { requireTenant } from '../tenant';

const scanParamsSchema = z.object({ scanId: z.string().min(1).max(64) });
const findingParamsSchema = z.object({ findingId: z.string().min(1).max(64) });

export async function registerFindingRoutes(app: FastifyInstance): Promise<void> {
  /**
   * Findings for one scan.
   *
   * Note the location fields (filePath, startLine) returned first-class: line-accurate
   * navigation is a core product requirement, not a detail of the raw tool output.
   */
  app.get('/v1/scans/:scanId/findings', async (request, reply) => {
    const tenant = requireTenant(request);
    const { scanId } = scanParamsSchema.parse(request.params);
    const query = listFindingsQuerySchema.parse(request.query ?? {});

    const scan = await app.prisma.scan.findFirst({
      where: { id: scanId, organizationId: tenant.organizationId },
      select: { id: true },
    });

    if (!scan) {
      return reply.code(404).send({ error: { code: 'SCAN_NOT_FOUND', message: 'Scan not found.' } });
    }

    const findings = await app.prisma.finding.findMany({
      where: {
        scanId: scan.id,
        organizationId: tenant.organizationId,
        ...(query.severity ? { severity: query.severity } : {}),
        ...(query.status ? { status: query.status } : {}),
        ...(query.kind ? { kind: query.kind } : {}),
        ...(query.cveId ? { cveIds: { has: query.cveId } } : {}),
        ...(query.filePath ? { filePath: { contains: query.filePath } } : {}),
      },
      orderBy: [{ severity: 'asc' }, { filePath: 'asc' }, { startLine: 'asc' }],
      take: query.limit,
      ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
    });

    return {
      items: findings.map((finding) => ({
        id: finding.id,
        fingerprint: finding.fingerprint,
        scanId: finding.scanId,
        repositoryId: finding.repositoryId,
        kind: finding.kind,
        scanner: finding.scanner,
        ruleId: finding.ruleId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        cvssScore: finding.cvssScore === null ? null : Number(finding.cvssScore),
        cweIds: finding.cweIds,
        cveIds: finding.cveIds,
        ghsaId: finding.ghsaId,
        status: finding.status,
        filePath: finding.filePath,
        startLine: finding.startLine,
        endLine: finding.endLine,
        packageName: finding.packageName,
        packageVersion: finding.packageVersion,
        fixedVersion: finding.fixedVersion,
        ecosystem: finding.ecosystem,
        detectedAt: finding.detectedAt.toISOString(),
      })),
      nextCursor: findings.length === query.limit ? findings[findings.length - 1]?.id : undefined,
    };
  });

  /**
   * Triage a finding.
   *
   * Suppressing writes a `FindingSuppression` keyed by fingerprint so the decision
   * survives future scans of the same issue.
   */
  app.patch('/v1/findings/:findingId', async (request, reply) => {
    const tenant = requireTenant(request);
    const { findingId } = findingParamsSchema.parse(request.params);
    const body = updateFindingRequestSchema.parse(request.body ?? {});

    const finding = await app.prisma.finding.findFirst({
      where: { id: findingId, organizationId: tenant.organizationId },
      select: { id: true, fingerprint: true, repositoryId: true, status: true },
    });

    if (!finding) {
      return reply.code(404).send({
        error: { code: 'FINDING_NOT_FOUND', message: 'Finding not found.' },
      });
    }

    const updated = await app.prisma.finding.update({
      where: { id: finding.id },
      data: {
        status: body.status,
        ...(body.status === 'RESOLVED' ? { resolvedAt: new Date() } : {}),
      },
      select: { id: true, status: true },
    });

    if (body.status === 'IGNORED' || body.status === 'FALSE_POSITIVE') {
      if (!body.reason) {
        return reply.code(400).send({
          error: {
            code: 'REASON_REQUIRED',
            message: 'A reason is required when ignoring a finding or marking it a false positive.',
          },
        });
      }

      await app.prisma.findingSuppression.upsert({
        where: {
          repositoryId_fingerprint: {
            repositoryId: finding.repositoryId,
            fingerprint: finding.fingerprint,
          },
        },
        update: { reason: body.reason, createdById: tenant.userId ?? null },
        create: {
          organizationId: tenant.organizationId,
          repositoryId: finding.repositoryId,
          fingerprint: finding.fingerprint,
          reason: body.reason,
          createdById: tenant.userId ?? null,
        },
      });
    }

    await app.prisma.auditLog.create({
      data: {
        organizationId: tenant.organizationId,
        actorId: tenant.userId ?? null,
        action: 'finding.status_changed',
        targetType: 'finding',
        targetId: finding.id,
        ipAddress: request.ip,
        metadata: { from: finding.status, to: body.status },
      },
    });

    return { id: updated.id, status: updated.status };
  });
}
