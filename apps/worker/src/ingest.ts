import { computeFingerprint, type FindingKindName } from '@syscanner/core';
import { prisma, type Prisma, type Severity } from '@syscanner/db';
import type { NormalizedFinding } from '@syscanner/scanners';

/**
 * Ingests normalized findings.
 *
 * Two properties matter here:
 *
 *  1. **Idempotence.** `@@unique([scanId, fingerprint])` plus `upsert` means a
 *     BullMQ retry cannot duplicate rows, so we never have to reconcile after a
 *     worker restart.
 *  2. **Bounded work.** A hostile repository can produce an unbounded number of
 *     findings. We cap the batch, write in chunks, and stop rather than letting
 *     one scan dominate the database.
 */

export interface IngestContext {
  scanId: string;
  organizationId: string;
  repositoryId: string;
  taskId?: string;
  maxFindings: number;
}

export interface IngestSummary {
  inserted: number;
  skipped: number;
  truncated: boolean;
}

const BATCH_SIZE = 250;

export async function ingestFindings(
  context: IngestContext,
  findings: readonly NormalizedFinding[],
): Promise<IngestSummary> {
  const truncated = findings.length > context.maxFindings;
  const accepted = findings.slice(0, context.maxFindings);
  let inserted = 0;
  let skipped = 0;

  // Deduplicate within the batch first: two tools can report the same issue, and
  // an upsert collision inside a single transaction would be wasteful.
  const byFingerprint = new Map<string, NormalizedFinding>();
  for (const finding of accepted) {
    const fingerprint = fingerprintFor(finding);
    if (!byFingerprint.has(fingerprint)) byFingerprint.set(fingerprint, finding);
  }

  skipped = accepted.length - byFingerprint.size;

  const entries = [...byFingerprint.entries()];

  for (let offset = 0; offset < entries.length; offset += BATCH_SIZE) {
    const chunk = entries.slice(offset, offset + BATCH_SIZE);

    await prisma.$transaction(
      chunk.map(([fingerprint, finding]) =>
        prisma.finding.upsert({
          where: { scanId_fingerprint: { scanId: context.scanId, fingerprint } },
          update: {
            lastSeenAt: new Date(),
            occurrenceCount: { increment: 1 },
          },
          create: {
            fingerprint,
            scanId: context.scanId,
            taskId: context.taskId ?? null,
            repositoryId: context.repositoryId,
            organizationId: context.organizationId,
            ...toDatabasePayload(finding),
          },
        }),
      ),
    );

    inserted += chunk.length;
  }

  await refreshScanAggregates(context.scanId);

  return { inserted, skipped, truncated };
}

/** Stable identity — must match the definition documented on `Finding.fingerprint`. */
export function fingerprintFor(finding: NormalizedFinding): string {
  return computeFingerprint({
    kind: finding.kind as FindingKindName,
    ruleId: finding.ruleId,
    filePath: finding.filePath,
    startLine: finding.startLine,
    snippetHash: finding.snippetHash,
    ecosystem: finding.ecosystem,
    packageName: finding.packageName,
  });
}

/**
 * Columns this mapper owns.
 *
 * The foreign keys and the fingerprint are set by `ingestFindings`, so they are
 * excluded here — otherwise spreading this object after the explicit fields would
 * silently overwrite them. Exported because the "format findings into a structured
 * database payload" step is worth testing and reusing on its own.
 */
export type FindingRow = Omit<
  Prisma.FindingUncheckedCreateInput,
  'id' | 'fingerprint' | 'scanId' | 'taskId' | 'repositoryId' | 'organizationId'
>;

/** Maps one normalized finding onto the columns of a `Finding` row. */
export function toDatabasePayload(finding: NormalizedFinding): FindingRow {
  return {
    // `kind` is guaranteed to be one of the ScannerKind enum members by the
    // adapters, which only ever emit values from that union.
    kind: finding.kind as FindingRow['kind'],
    scanner: finding.scanner,
    ruleId: finding.ruleId,
    title: finding.title,
    description: finding.description ?? null,
    category: finding.category ?? null,
    references: finding.references,
    severity: finding.severity as Severity,
    cvssScore: finding.cvssScore === undefined ? null : String(finding.cvssScore),
    cvssVector: finding.cvssVector ?? null,
    cweIds: finding.cweIds,
    cveIds: finding.cveIds,
    ghsaId: finding.ghsaId ?? null,
    filePath: finding.filePath ?? null,
    startLine: finding.startLine ?? null,
    endLine: finding.endLine ?? null,
    startColumn: finding.startColumn ?? null,
    endColumn: finding.endColumn ?? null,
    snippetHash: finding.snippetHash ?? null,
    packageName: finding.packageName ?? null,
    packageVersion: finding.packageVersion ?? null,
    fixedVersion: finding.fixedVersion ?? null,
    ecosystem: finding.ecosystem ?? null,
    dependencyPath: finding.dependencyPath ?? null,
  };
}

/**
 * Recomputes the denormalized counters on `Scan`.
 *
 * Dashboards read these directly, so they must be refreshed after ingest rather
 * than computed with COUNT(*) on every request.
 */
export async function refreshScanAggregates(scanId: string): Promise<void> {
  const grouped = await prisma.finding.groupBy({
    by: ['severity'],
    where: { scanId },
    _count: { _all: true },
  });

  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
    UNKNOWN: 0,
  };

  for (const group of grouped) {
    counts[group.severity] = group._count._all;
  }

  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);

  await prisma.scan.update({
    where: { id: scanId },
    data: {
      totalFindings: total,
      criticalCount: counts.CRITICAL ?? 0,
      highCount: counts.HIGH ?? 0,
      mediumCount: counts.MEDIUM ?? 0,
      lowCount: counts.LOW ?? 0,
      infoCount: (counts.INFO ?? 0) + (counts.UNKNOWN ?? 0),
    },
  });
}
