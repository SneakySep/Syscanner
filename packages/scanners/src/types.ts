import type { FindingKindName, SeverityName } from '@syscanner/core';

/**
 * The tool-agnostic shape every scanner adapter must produce.
 *
 * Adapters do not touch the database and do not send data anywhere: they turn a
 * tool invocation plus its machine-readable output into this structure. Keeping
 * the boundary this narrow is what allows a hostile repository's output to be
 * validated in one place.
 */
export interface NormalizedFinding {
  kind: FindingKindName;
  /** Producing tool, e.g. "semgrep". */
  scanner: string;
  ruleId: string;
  title: string;
  description?: string;
  category?: string;

  severity: SeverityName;
  cvssScore?: number;
  cvssVector?: string;
  cweIds: string[];
  cveIds: string[];
  ghsaId?: string;
  owaspCategory?: string;

  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  /**
   * Hash of the matched snippet. The snippet itself is intentionally not part of
   * this structure — it may contain a live credential.
   */
  snippetHash?: string;

  packageName?: string;
  packageVersion?: string;
  fixedVersion?: string;
  ecosystem?: string;
  dependencyPath?: string;

  references: string[];
}

/** SARIF severity levels, per the OASIS spec. */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface ParseOptions {
  scanner: string;
  kind: FindingKindName;
  /** Refuse to parse artifacts larger than this. Protects the control plane. */
  maxBytes?: number;
  /** Hard cap on findings extracted from one artifact. */
  maxResults?: number;
}

export interface ParseResult {
  findings: NormalizedFinding[];
  /** True when the artifact hit a size/result cap and was truncated on purpose. */
  truncated: boolean;
  /** Non-fatal problems (skipped malformed results, cap hits). */
  warnings: string[];
}
