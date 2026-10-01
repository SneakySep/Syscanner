import type { FastifyInstance } from 'fastify';

import { requireTenant } from '../tenant';

/**
 * Repository listing.
 *
 * Read-only and tenant-scoped: the `organizationId` filter comes from the resolved
 * tenant context, never from the request, so a client cannot enumerate another
 * tenant's repositories even by guessing ids.
 */
export async function registerRepositoryRoutes(app: FastifyInstance): Promise<void> {
  app.get('/v1/repositories', async (request) => {
    const tenant = requireTenant(request);

    const repositories = await app.prisma.repository.findMany({
      where: { organizationId: tenant.organizationId, deletedAt: null },
      // Most recently scanned first; never-scanned repositories sort by name.
      orderBy: [{ lastScanAt: 'desc' }, { fullName: 'asc' }],
      select: {
        id: true,
        fullName: true,
        provider: true,
        defaultBranch: true,
        isPrivate: true,
        language: true,
        lastScanAt: true,
        _count: { select: { scans: true, findings: true } },
      },
    });

    return {
      items: repositories.map((repository) => ({
        id: repository.id,
        fullName: repository.fullName,
        provider: repository.provider,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate,
        language: repository.language,
        lastScanAt: repository.lastScanAt?.toISOString() ?? null,
        scanCount: repository._count.scans,
        findingCount: repository._count.findings,
      })),
    };
  });
}
