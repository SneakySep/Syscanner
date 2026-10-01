import Link from 'next/link';

import { apiFetch, ApiError } from '@/lib/api';

export const dynamic = 'force-dynamic';

interface RepositorySummary {
  id: string;
  fullName: string;
  provider: string;
  defaultBranch: string;
  isPrivate: boolean;
  language: string | null;
  lastScanAt: string | null;
  scanCount: number;
  findingCount: number;
}

export default async function RepositoriesPage() {
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

  if (problem) {
    return (
      <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
        {problem}
      </div>
    );
  }

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Repositories</h1>
        <p className="mt-1 text-sm text-slate-400">
          Connected repositories. Every scan is pinned to a commit, and findings are compared across
          scans by fingerprint.
        </p>
      </div>

      <ul className="divide-y divide-slate-800 overflow-hidden rounded-lg border border-slate-800">
        {repositories.map((repository) => (
          <li
            key={repository.id}
            className="flex flex-wrap items-center justify-between gap-2 bg-panel px-4 py-3"
          >
            <div>
              <p className="font-medium text-slate-200">{repository.fullName}</p>
              <p className="text-xs text-slate-500">
                {repository.provider.toLowerCase()} · {repository.defaultBranch}
                {repository.language ? ` · ${repository.language}` : ''}
                {repository.isPrivate ? ' · private' : ''}
              </p>
            </div>
            <div className="text-right text-xs text-slate-500">
              <p>
                {repository.scanCount} scan{repository.scanCount === 1 ? '' : 's'} ·{' '}
                {repository.findingCount} finding{repository.findingCount === 1 ? '' : 's'}
              </p>
              <p>
                {repository.lastScanAt
                  ? `last scanned ${new Date(repository.lastScanAt).toLocaleString()}`
                  : 'never scanned'}
              </p>
            </div>
          </li>
        ))}

        {repositories.length === 0 ? (
          <li className="bg-panel px-4 py-6 text-center text-sm text-slate-500">
            No repositories connected yet. Run{' '}
            <code className="font-mono text-slate-400">pnpm db:seed</code> for sample data, or{' '}
            <Link href="/" className="text-sky-400 hover:text-sky-300">
              return to the overview
            </Link>
            .
          </li>
        ) : null}
      </ul>
    </section>
  );
}
