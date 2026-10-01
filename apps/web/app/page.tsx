import { SeverityBadge } from '@syscanner/ui';
import Link from 'next/link';

import { apiFetch, ApiError } from '@/lib/api';

/** Scan data is always live: never serve a cached dashboard. */
export const dynamic = 'force-dynamic';

interface RepositorySummary {
  id: string;
  fullName: string;
}

/**
 * Overview page.
 *
 * Rendered as a Server Component so the API is called from the server, and the
 * page degrades to an explanatory empty state when the control plane is not
 * running (a very common state during local setup).
 */
export default async function OverviewPage() {
  let repositories: RepositorySummary[] = [];
  let problem: string | undefined;

  try {
    const response = await apiFetch<{ items: RepositorySummary[] }>('/v1/repositories');
    repositories = response.items ?? [];
  } catch (error) {
    problem =
      error instanceof ApiError
        ? `${error.code}: ${error.message}`
        : 'The Syscanner API is unreachable.';
  }

  return (
    <section className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-white">Security overview</h1>
        <p className="mt-1 text-sm text-slate-400">
          Findings from static analysis, secret detection and dependency scanning, aggregated per
          repository.
        </p>
      </div>

      {problem ? (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
          <p className="font-medium">The control plane is not reachable.</p>
          <p className="mt-1 text-amber-200/80">{problem}</p>
          <p className="mt-2 text-amber-200/80">
            Start it with <code className="font-mono">pnpm --filter @syscanner/api dev</code> and
            bring up Postgres/Redis with <code className="font-mono">pnpm infra:up</code>.
          </p>
        </div>
      ) : repositories.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-panel p-6 text-sm text-slate-400">
          <p className="font-medium text-slate-200">No repositories connected yet.</p>
          <p className="mt-1">
            Connect a repository to start scanning. Run{' '}
            <code className="font-mono">pnpm db:seed</code> for sample data.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800">
          {repositories.map((repository) => (
            <li key={repository.id} className="flex items-center justify-between bg-panel px-4 py-3">
              <span className="font-medium text-slate-200">{repository.fullName}</span>
              <Link
                href={`/repositories`}
                className="text-sm text-sky-400 hover:text-sky-300"
              >
                View scans
              </Link>
            </li>
          ))}
        </ul>
      )}

      <div className="rounded-lg border border-slate-800 bg-panel p-6">
        <h2 className="text-sm font-semibold text-slate-200">Severity legend</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
            <SeverityBadge key={severity} severity={severity} />
          ))}
        </div>
      </div>
    </section>
  );
}
