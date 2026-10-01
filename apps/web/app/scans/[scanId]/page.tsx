import { SeverityBadge } from '@syscanner/ui';

import { apiFetch, ApiError } from '@/lib/api';

export const dynamic = 'force-dynamic';

interface ScanDetail {
  id: string;
  repositoryFullName: string;
  status: string;
  branch: string | null;
  commitSha: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  durationMs: number | null;
  tasks: Array<{ id: string; kind: string; tool: string; status: string; durationMs: number | null }>;
}

interface FindingRow {
  id: string;
  kind: string;
  ruleId: string;
  title: string;
  severity: string;
  cveIds: string[];
  cweIds: string[];
  filePath: string | null;
  startLine: number | null;
  packageName: string | null;
  packageVersion: string | null;
  fixedVersion: string | null;
}

export default async function ScanPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;

  try {
    const [scan, findings] = await Promise.all([
      apiFetch<ScanDetail>(`/v1/scans/${scanId}`),
      apiFetch<{ items: FindingRow[] }>(`/v1/scans/${scanId}/findings?limit=50`),
    ]);

    return (
      <section className="space-y-8">
        <header>
          <h1 className="text-2xl font-semibold text-white">{scan.repositoryFullName}</h1>
          <p className="mt-1 font-mono text-xs text-slate-400">
            {scan.branch ?? 'detached'} @ {scan.commitSha.slice(0, 12)} — {scan.status}
          </p>
        </header>

        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity="CRITICAL" count={scan.criticalCount} />
          <SeverityBadge severity="HIGH" count={scan.highCount} />
          <SeverityBadge severity="MEDIUM" count={scan.mediumCount} />
          <SeverityBadge severity="LOW" count={scan.lowCount} />
          <SeverityBadge severity="INFO" count={scan.infoCount} />
        </div>

        <section>
          <h2 className="text-sm font-semibold text-slate-200">Scanner tasks</h2>
          <ul className="mt-2 grid gap-2 sm:grid-cols-2">
            {scan.tasks.map((task) => (
              <li
                key={task.id}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-panel px-4 py-2 text-sm"
              >
                <span className="text-slate-300">
                  {task.kind} <span className="text-slate-500">({task.tool})</span>
                </span>
                <span className="text-slate-400">
                  {task.status}
                  {task.durationMs ? ` · ${(task.durationMs / 1000).toFixed(1)}s` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-slate-200">
            Findings <span className="text-slate-500">({scan.totalFindings})</span>
          </h2>
          <div className="mt-2 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Finding</th>
                  <th className="px-4 py-2">Location</th>
                  <th className="px-4 py-2">Identifiers</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {findings.items.map((finding) => (
                  <tr key={finding.id} className="align-top">
                    <td className="px-4 py-3">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-200">{finding.title}</p>
                      <p className="font-mono text-xs text-slate-500">{finding.ruleId}</p>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-sky-300">
                      {finding.filePath ? (
                        <>
                          {finding.filePath}
                          {finding.startLine ? `:${finding.startLine}` : ''}
                        </>
                      ) : finding.packageName ? (
                        <>
                          {finding.packageName}@{finding.packageVersion}
                          {finding.fixedVersion ? ` → ${finding.fixedVersion}` : ''}
                        </>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {[...finding.cveIds, ...finding.cweIds].join(', ') || '—'}
                    </td>
                  </tr>
                ))}
                {findings.items.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-slate-500">
                      No findings recorded for this scan.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      </section>
    );
  } catch (error) {
    const message =
      error instanceof ApiError ? `${error.code}: ${error.message}` : 'Unable to load this scan.';

    return (
      <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
        {message}
      </div>
    );
  }
}
