import Link from 'next/link';

// Imported from the file directly, not from the barrel: the barrel also exports
// `monaco-setup`, which evaluates monaco-editor at module load and must stay out of
// the server bundle.
import { CodeViewerMount } from '@/components/code-viewer/CodeViewerMount';
import {
  FIXTURE_CODE,
  FIXTURE_FINDINGS,
  FIXTURE_LANGUAGE,
  FIXTURE_PATH,
} from '@/lib/demo/vulnerable-file-fixture';

export const dynamic = 'force-dynamic';

/**
 * Code viewer demo.
 *
 * Deliberately explicit about being a demo: the architecture never persists file
 * contents (a `Finding` stores a snippet hash, not the snippet) and there is no source
 * endpoint yet, so the viewer is fed a fixture. Labelling it in the UI is the point —
 * an unlabelled mock reads as a working feature.
 */
export default async function CodeViewerPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;

  return (
    <section className="space-y-6">
      <div>
        <Link
          href={`/scans/${scanId}`}
          className="text-sm text-sky-400 hover:text-sky-300"
        >
          ← Back to findings
        </Link>
        <h1 className="mt-2 text-2xl font-semibold text-white">Code viewer</h1>
        <p className="mt-1 text-sm text-slate-400">
          Vulnerable lines are highlighted in the editor. Selecting a finding scrolls the editor to
          that line and moves the cursor onto it.
        </p>
      </div>

      <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
        <p className="font-medium">Demo data — no scan produced this.</p>
        <p className="mt-1 text-amber-200/80">
          The platform does not persist file contents (findings store a snippet hash, not the
          source) and there is no source-code endpoint yet, so this page renders a fixture. Wiring
          it to real data needs a repository-contents endpoint plus a remediation field on findings.
        </p>
      </div>

      <CodeViewerMount
        code={FIXTURE_CODE}
        language={FIXTURE_LANGUAGE}
        path={FIXTURE_PATH}
        findings={FIXTURE_FINDINGS}
        title={FIXTURE_PATH}
      />
    </section>
  );
}