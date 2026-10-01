export type SeverityName = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN';

/** Ordered most-severe-first; never rely on alphabetical ordering of these strings. */
export const SEVERITY_ORDER: readonly SeverityName[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
  'UNKNOWN',
] as const;

const RANK: Record<SeverityName, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0,
};

/**
 * Maps a CVSS v3 base score to a Severity bucket.
 *
 * CVSS v3.1 specification ranges. A missing/NaN score yields UNKNOWN rather than
 * silently defaulting to a low severity — fail visible, not quiet.
 */
export function severityFromCvss(score: number | null | undefined): SeverityName {
  if (score === null || score === undefined || Number.isNaN(score)) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0.0) return 'LOW';
  return 'INFO';
}

export function severityRank(severity: SeverityName): number {
  return RANK[severity] ?? 0;
}

/** True when `severity` is at least as severe as `threshold`. */
export function meetsThreshold(severity: SeverityName, threshold: SeverityName): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export function maxSeverity(severities: readonly SeverityName[]): SeverityName {
  return severities.reduce<SeverityName>(
    (worst, current) => (severityRank(current) > severityRank(worst) ? current : worst),
    'UNKNOWN',
  );
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Folds CVSS + tool-reported severity into the single bucket we persist.
 *
 * Tools disagree, so we take the more severe of the two: under-reporting a
 * vulnerability is a security failure, over-reporting is merely noise.
 */
export function resolveSeverity(
  toolSeverity: SeverityName | null | undefined,
  cvssScore: number | null | undefined,
): SeverityName {
  const fromCvss = severityFromCvss(cvssScore);
  const fromTool = toolSeverity ?? 'UNKNOWN';
  return maxSeverity([fromCvss, fromTool]);
}

export function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function tallySeverities(severities: readonly SeverityName[]): SeverityCounts {
  const counts = emptySeverityCounts();
  for (const severity of severities) {
    switch (severity) {
      case 'CRITICAL':
        counts.critical += 1;
        break;
      case 'HIGH':
        counts.high += 1;
        break;
      case 'MEDIUM':
        counts.medium += 1;
        break;
      case 'LOW':
      case 'INFO':
        // INFO is folded into LOW for the gate counters: it is never blocking.
        if (severity === 'LOW') counts.low += 1;
        else counts.info += 1;
        break;
      default:
        break;
    }
  }
  return counts;
}
