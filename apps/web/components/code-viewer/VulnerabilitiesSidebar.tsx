'use client';

import { severityClassName, severityLabel } from '@syscanner/ui';
import { useMemo } from 'react';

import { severityCounts, sortFindings, toPresentationSeverity, type ViewerFinding } from './decorations';

export interface VulnerabilitiesSidebarProps {
  findings: readonly ViewerFinding[];
  activeFindingId?: string | null;
  onSelectFinding?: (findingId: string) => void;
  /** True when the decoration cap was reached, so the list is not the whole story. */
  truncated?: boolean;
}

/**
 * Interactive findings panel.
 *
 * Rows are real buttons rather than clickable divs: this is an interactive list, so
 * it should be reachable and operable by keyboard, and the active row should announce
 * itself through `aria-current`.
 */
export function VulnerabilitiesSidebar({
  findings,
  activeFindingId,
  onSelectFinding,
  truncated = false,
}: VulnerabilitiesSidebarProps) {
  const ordered = useMemo(() => sortFindings(findings), [findings]);
  const counts = useMemo(() => severityCounts(findings), [findings]);

  return (
    <aside
      aria-label="Vulnerabilities"
      className="flex w-full flex-col overflow-hidden rounded-lg border border-slate-800 bg-panel lg:w-96"
    >
      <header className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-200">
          Vulnerabilities <span className="text-slate-500">({ordered.length})</span>
        </h2>
        <div className="mt-2 flex flex-wrap gap-1">
          {Object.entries(counts).map(([severity, count]) => (
            <span
              key={severity}
              className={`rounded-full px-2 py-0.5 text-xs font-semibold ${severityClassName(severity)}`}
            >
              {severityLabel(severity)} {count}
            </span>
          ))}
          {ordered.length === 0 ? (
            <span className="text-xs text-slate-500">No findings for this file.</span>
          ) : null}
        </div>
      </header>

      <ul className="flex-1 divide-y divide-slate-800 overflow-y-auto">
        {ordered.map((finding) => {
          const isActive = finding.id === activeFindingId;
          const severity = toPresentationSeverity(finding.severity);

          return (
            <li key={finding.id}>
              <button
                type="button"
                aria-current={isActive ? 'true' : undefined}
                onClick={() => onSelectFinding?.(finding.id)}
                className={`w-full px-4 py-3 text-left transition-colors hover:bg-slate-800/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${
                  isActive ? 'bg-slate-800' : ''
                }`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-semibold ${severityClassName(severity)}`}
                  >
                    {severityLabel(severity)}
                  </span>
                  <span className="font-mono text-xs text-sky-300">L{finding.line}</span>
                </div>

                <p className="mt-1.5 text-sm font-medium text-slate-200">{finding.title}</p>

                {finding.ruleId ? (
                  <p className="mt-0.5 truncate font-mono text-xs text-slate-500">{finding.ruleId}</p>
                ) : null}

                {/* Suggested fixes are scanner-authored text about a hostile
                    repository, so they render as plain text — never as markup. */}
                {finding.suggestedFix ? (
                  <p className="mt-2 rounded border border-slate-700 bg-slate-900/60 px-2 py-1 text-xs text-emerald-300">
                    Fix: {finding.suggestedFix}
                  </p>
                ) : (
                  <p className="mt-2 text-xs text-slate-500">
                    No automated fix available for this rule.
                  </p>
                )}
              </button>
            </li>
          );
        })}
      </ul>

      {truncated ? (
        <footer className="border-t border-slate-800 px-4 py-2 text-xs text-amber-300">
          Highlighting was capped; not every finding in this file is shown.
        </footer>
      ) : null}
    </aside>
  );
}