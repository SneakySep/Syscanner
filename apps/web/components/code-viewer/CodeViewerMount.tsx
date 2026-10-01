'use client';

import dynamic from 'next/dynamic';

import type { VulnerabilityCodeViewerProps } from './VulnerabilityCodeViewer';

/**
 * Loads the viewer on the client only.
 *
 * `monaco-editor` reaches for `window` while its module is evaluated, so it cannot be
 * server-rendered — and `next/dynamic` with `ssr: false` is only permitted inside a
 * Client Component, which is why this thin wrapper exists. It also keeps Monaco out
 * of the server bundle entirely.
 */
const VulnerabilityCodeViewer = dynamic(
  () => import('./VulnerabilityCodeViewer').then((module) => module.VulnerabilityCodeViewer),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[600px] items-center justify-center rounded-lg border border-slate-800 bg-panel text-sm text-slate-500">
        Loading code viewer…
      </div>
    ),
  },
);

export function CodeViewerMount(props: VulnerabilityCodeViewerProps) {
  return <VulnerabilityCodeViewer {...props} />;
}