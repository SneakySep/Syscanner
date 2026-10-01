import type { FindingKindName } from './fingerprint';
import { meetsThreshold, type SeverityCounts, type SeverityName } from './severity';

/**
 * Per-repository scan policy. Persisted as `Repository.scanConfig` JSON so that a
 * policy change does not require a migration, and versioned on each Scan so old
 * results stay explainable.
 */
export interface ScanPolicy {
  scanners: FindingKindName[];
  /** Glob-ish prefixes that are skipped before scanning, e.g. "vendor/**". */
  excludePaths: string[];
  /** Lowest severity that blocks a merge / fails the quality gate. */
  failOn: SeverityName;
}

export const DEFAULT_SCAN_POLICY: ScanPolicy = {
  scanners: ['SAST', 'SECRETS', 'DEPENDENCY'],
  excludePaths: [],
  failOn: 'HIGH',
};

/** Coerces persisted JSON into a valid policy, falling back to safe defaults. */
export function parseScanPolicy(raw: unknown): ScanPolicy {
  if (raw === null || typeof raw !== 'object') return { ...DEFAULT_SCAN_POLICY };
  const candidate = raw as Partial<ScanPolicy>;

  return {
    scanners:
      Array.isArray(candidate.scanners) && candidate.scanners.length > 0
        ? candidate.scanners
        : DEFAULT_SCAN_POLICY.scanners,
    excludePaths: Array.isArray(candidate.excludePaths) ? candidate.excludePaths : [],
    failOn: candidate.failOn ?? DEFAULT_SCAN_POLICY.failOn,
  };
}

const GLOB_CACHE = new Map<string, RegExp>();

/**
 * Converts a glob to a RegExp.
 *
 * Supports the forms that actually appear in scan policies:
 *   "vendor/**"    -> anything under vendor/
 *   "**&#47;*.min.js" -> any .min.js file at any depth (including the root)
 *   "Dockerfile"   -> an exact path match
 */
function globToRegExp(pattern: string): RegExp {
  const cached = GLOB_CACHE.get(pattern);
  if (cached) return cached;

  let body = pattern;
  let prefix = '^';

  // A leading "**/" should also match files at the repository root.
  if (body.startsWith('**/')) {
    prefix = '^(?:.*/)?';
    body = body.slice(3);
  }

  const escaped = body.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const source = escaped
    .replace(/\*\*/g, '\u0000') // placeholder so "**" survives the "*" pass
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '[^/]');

  const regex = new RegExp(`${prefix}${source}$`);
  GLOB_CACHE.set(pattern, regex);
  return regex;
}

/** True when `filePath` matches any of the policy's exclude patterns. */
export function isPathExcluded(filePath: string, patterns: readonly string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  return patterns.some((pattern) => {
    const clean = pattern.replace(/\\/g, '/').trim();
    if (clean.length === 0) return false;
    return globToRegExp(clean).test(normalized);
  });
}

export interface QualityGateResult {
  passed: boolean;
  blockingFindings: number;
}

/** The CI gate: does this scan block the build under the given policy? */
export function evaluateQualityGate(
  counts: SeverityCounts,
  failOn: SeverityName,
): QualityGateResult {
  const buckets: Array<[SeverityName, number]> = [
    ['CRITICAL', counts.critical],
    ['HIGH', counts.high],
    ['MEDIUM', counts.medium],
    ['LOW', counts.low],
    ['INFO', counts.info],
  ];

  const blockingFindings = buckets
    .filter(([severity]) => meetsThreshold(severity, failOn))
    .reduce((total, [, count]) => total + count, 0);

  return { passed: blockingFindings === 0, blockingFindings };
}
