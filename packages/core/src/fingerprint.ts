import { createHash } from 'node:crypto';

export type FindingKindName =
  | 'SAST'
  | 'SECRETS'
  | 'DEPENDENCY'
  | 'LICENSE'
  | 'IAC'
  | 'CONTAINER'
  | 'SBOM';

export interface FingerprintInput {
  kind: FindingKindName;
  ruleId: string;
  /** Repository-relative path, e.g. "src/api/users.ts". */
  filePath?: string | null;
  startLine?: number | null;
  /**
   * Hash of the matched snippet. Including it means an issue that is merely
   * *moved* to another line is still recognised as the same issue, while a
   * genuinely different match at the same line is treated as new.
   */
  snippetHash?: string | null;
  /** Dependency findings identify a package rather than a location. */
  ecosystem?: string | null;
  packageName?: string | null;
}

/** Normalises Windows separators and leading "./" so fingerprints are portable. */
export function normalizeRepoPath(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/{2,}/g, '/').trim();
}

/**
 * Stable identity of a finding across scans.
 *
 * SAST / secret findings: sha256(kind | ruleId | normalizedPath | startLine | snippetHash)
 * Dependency findings:    sha256(kind | ruleId | ecosystem | packageName)
 *
 * Location is part of the identity on purpose: line-accurate tracking is a product
 * requirement, so a finding that moves must be re-evaluated rather than silently
 * inherited.
 */
export function computeFingerprint(input: FingerprintInput): string {
  const parts =
    input.kind === 'DEPENDENCY' || input.kind === 'LICENSE' || input.kind === 'SBOM'
      ? [
          input.kind,
          input.ruleId,
          (input.ecosystem ?? '').toLowerCase(),
          (input.packageName ?? '').toLowerCase(),
        ]
      : [
          input.kind,
          input.ruleId,
          input.filePath ? normalizeRepoPath(input.filePath) : '',
          input.startLine === null || input.startLine === undefined ? '' : String(input.startLine),
          input.snippetHash ?? '',
        ];

  return createHash('sha256').update(parts.join('|')).digest('hex');
}

/** sha256 of a matched snippet, used instead of storing the snippet itself. */
export function hashSnippet(snippet: string): string {
  return createHash('sha256').update(snippet, 'utf8').digest('hex');
}

/** sha256 of a scan's idempotency inputs. */
export function computeInputFingerprint(parts: {
  repositoryId: string;
  commitSha: string;
  policyVersion: number;
  toolVersions: Record<string, string>;
}): string {
  const tools = Object.keys(parts.toolVersions)
    .sort()
    .map((key) => `${key}@${parts.toolVersions[key]}`)
    .join(',');

  return createHash('sha256')
    .update(
      [parts.repositoryId, parts.commitSha, String(parts.policyVersion), tools].join('|'),
      'utf8',
    )
    .digest('hex');
}
