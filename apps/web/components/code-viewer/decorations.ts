import { SEVERITY_PRESENTATION, type PresentationSeverity } from '@syscanner/ui';

/**
 * Pure logic for the vulnerability code viewer.
 *
 * Deliberately free of React and of any `monaco-editor` import: this is the half of
 * the feature that can actually be tested in Vitest, and it is where the real
 * decisions live (which lines get highlighted, in what colour, in what order).
 * Monaco's own rendering cannot be meaningfully asserted headlessly, so it is kept
 * out of this module on purpose.
 */

/** A finding as the viewer needs it, decoupled from the API response shape. */
export interface ViewerFinding {
  id: string;
  /** One of the six severities; never assume only three. */
  severity: string;
  line: number;
  endLine?: number;
  title: string;
  suggestedFix?: string;
  ruleId?: string;
}

/**
 * Decoration class names.
 *
 * These must be **complete literal strings**: Tailwind scans source files for literals
 * and cannot see a dynamically composed `bg-${severity}-500`, so that class would
 * never be emitted and the highlight would silently not appear. Monaco also injects
 * these into its own DOM, which Tailwind never scans, so they have to exist as
 * literals here and be picked up from this file's source.
 *
 * `border-l-2` gives a solid severity bar in the left margin; the translucent fill
 * keeps the code underneath readable.
 */
export const DECORATION_CLASSES: Record<PresentationSeverity, string> = {
  CRITICAL: 'bg-red-500/20 border-l-2 border-red-500',
  HIGH: 'bg-orange-500/20 border-l-2 border-orange-500',
  MEDIUM: 'bg-amber-400/20 border-l-2 border-amber-400',
  LOW: 'bg-sky-500/20 border-l-2 border-sky-500',
  INFO: 'bg-slate-400/20 border-l-2 border-slate-400',
  UNKNOWN: 'bg-slate-400/20 border-l-2 border-slate-400',
};

/** Glyph-margin marker colours, for the icon strip beside the line numbers. */
export const DECORATION_GLYPH_CLASSES: Record<PresentationSeverity, string> = {
  CRITICAL: 'text-red-500',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-amber-400',
  LOW: 'text-sky-500',
  INFO: 'text-slate-400',
  UNKNOWN: 'text-slate-400',
};

/** Overview-ruler tick colours, matching the severity palette. */
const OVERVIEW_RULER_COLORS: Record<PresentationSeverity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#fbbf24',
  LOW: '#0ea5e9',
  INFO: '#94a3b8',
  UNKNOWN: '#94a3b8',
};

/**
 * Upper bound on decorations.
 *
 * A hostile or merely noisy repository can emit tens of thousands of findings; Monaco
 * degrades badly past a few thousand decorations and the sidebar becomes unusable.
 * Callers get a truthful `truncated` flag rather than a silently shorter list.
 */
export const MAX_DECORATIONS = 2_000;

export function isPresentationSeverity(severity: string): severity is PresentationSeverity {
  return Object.prototype.hasOwnProperty.call(SEVERITY_PRESENTATION, severity);
}

/** Maps an unknown severity onto a known one, so styling can never come back empty. */
export function toPresentationSeverity(severity: string): PresentationSeverity {
  return isPresentationSeverity(severity) ? severity : 'UNKNOWN';
}

/** Rank used for ordering. Lower is more severe; mirrors the canonical UI order. */
export function severityRank(severity: string): number {
  return SEVERITY_PRESENTATION[toPresentationSeverity(severity)].order;
}

/**
 * Orders findings most-severe-first, then by line, then by id for stability.
 *
 * The id tiebreak matters: without it two findings on the same line could swap places
 * between renders, because `Array.prototype.sort` is only guaranteed stable in
 * modern engines and the sidebar order should not depend on input order.
 */
export function sortFindings(findings: readonly ViewerFinding[]): ViewerFinding[] {
  return [...findings].sort((left, right) => {
    const bySeverity = severityRank(left.severity) - severityRank(right.severity);
    if (bySeverity !== 0) return bySeverity;

    const byLine = left.line - right.line;
    if (byLine !== 0) return byLine;

    return left.id.localeCompare(right.id);
  });
}

/** Counts findings per severity, for the sidebar header. */
export function severityCounts(findings: readonly ViewerFinding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
}

export interface ClampedRange {
  startLineNumber: number;
  endLineNumber: number;
  clamped: boolean;
}

/**
 * Clamps a finding's range to the lines that actually exist in the document.
 *
 * Findings are claims about a commit, not necessarily about the exact string the
 * viewer was handed — a mismatch is normal, not exceptional. A line past the end of
 * the buffer would otherwise make Monaco throw on `setPosition`.
 */
export function clampFindingToDocument(
  finding: ViewerFinding,
  totalLines: number,
): ClampedRange | undefined {
  if (!Number.isFinite(finding.line) || totalLines < 1) return undefined;

  const startLineNumber = Math.max(1, Math.min(Math.trunc(finding.line), totalLines));

  const rawEnd = finding.endLine ?? finding.line;
  const normalisedEnd = Number.isFinite(rawEnd) ? Math.trunc(rawEnd) : startLineNumber;
  const endLineNumber = Math.max(startLineNumber, Math.min(normalisedEnd, totalLines));

  return {
    startLineNumber,
    endLineNumber,
    clamped: startLineNumber !== finding.line || endLineNumber !== rawEnd,
  };
}

export interface DecorationOptions {
  /** Structurally compatible with Monaco's `IModelDecorationOptions` — no monaco import. */
  isWholeLine: true;
  className: string;
  glyphMarginClassName: string;
  linesDecorationsClassName: string;
  overviewRuler: { color: string; position: number };
  hoverMessage: { value: string };
}

export interface BuiltDecoration {
  findingId: string;
  range: { startLineNumber: number; startColumn: number; endLineNumber: number; endColumn: number };
  options: DecorationOptions;
}

export interface BuildDecorationsResult {
  decorations: BuiltDecoration[];
  /** Findings whose line fell outside the document and had to be anchored. */
  clamped: ViewerFinding[];
  /** True when MAX_DECORATIONS was hit and the tail was dropped. */
  truncated: boolean;
  /** Findings that could not be placed at all (non-numeric or below line 1). */
  skipped: ViewerFinding[];
}

/**
 * Turns findings into Monaco decoration descriptors.
 *
 * Pure and total: it never throws and never returns a range outside the document, so
 * the React layer can pass its output straight to `createDecorationsCollection`.
 * Hover text is assembled from the finding's own fields and is plain text — Monaco
 * renders `hoverMessage` as markdown, so it must not be treated as HTML.
 */
export function buildDecorations(
  findings: readonly ViewerFinding[],
  totalLines: number,
  maxDecorations: number = MAX_DECORATIONS,
): BuildDecorationsResult {
  const ordered = sortFindings(findings);
  const clamped: ViewerFinding[] = [];
  const skipped: ViewerFinding[] = [];
  const decorations: BuiltDecoration[] = [];
  let truncated = false;

  for (const finding of ordered) {
    if (decorations.length >= maxDecorations) {
      truncated = true;
      break;
    }

    const range = clampFindingToDocument(finding, totalLines);
    if (!range) {
      skipped.push(finding);
      continue;
    }

    if (range.clamped) clamped.push(finding);

    const severity = toPresentationSeverity(finding.severity);
    const hover = [finding.title, finding.suggestedFix ? `Fix: ${finding.suggestedFix}` : '']
      .filter((part) => part.length > 0)
      .join('\n\n');

    decorations.push({
      findingId: finding.id,
      range: {
        startLineNumber: range.startLineNumber,
        // Columns are not modelled: whole-line highlighting is the requirement, and
        // the API does not currently return column data at all.
        startColumn: 1,
        endLineNumber: range.endLineNumber,
        endColumn: 1,
      },
      options: {
        isWholeLine: true,
        className: DECORATION_CLASSES[severity],
        glyphMarginClassName: DECORATION_GLYPH_CLASSES[severity],
        linesDecorationsClassName: DECORATION_CLASSES[severity],
        overviewRuler: { color: OVERVIEW_RULER_COLORS[severity], position: 4 },
        hoverMessage: { value: hover.length > 0 ? hover : finding.title },
      },
    });
  }

  return { decorations, clamped, truncated, skipped };
}

/** Line number to reveal for a finding, or undefined when it cannot be placed. */
export function lineForFinding(
  finding: ViewerFinding | undefined,
  totalLines: number,
): number | undefined {
  if (!finding) return undefined;
  return clampFindingToDocument(finding, totalLines)?.startLineNumber;
}