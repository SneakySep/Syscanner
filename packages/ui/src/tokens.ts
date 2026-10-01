/**
 * Presentation metadata for severities.
 *
 * Kept in a shared package so the API, the dashboard and exported reports all
 * agree on colours and labels. The ordering here is the canonical one — never
 * sort severities alphabetically.
 */
export const SEVERITY_PRESENTATION = {
  CRITICAL: { label: 'Critical', className: 'bg-red-600 text-white', order: 0 },
  HIGH: { label: 'High', className: 'bg-orange-500 text-white', order: 1 },
  MEDIUM: { label: 'Medium', className: 'bg-amber-400 text-black', order: 2 },
  LOW: { label: 'Low', className: 'bg-sky-500 text-white', order: 3 },
  INFO: { label: 'Info', className: 'bg-slate-400 text-white', order: 4 },
  UNKNOWN: { label: 'Unknown', className: 'bg-slate-300 text-black', order: 5 },
} as const;

export type PresentationSeverity = keyof typeof SEVERITY_PRESENTATION;

export function severityClassName(severity: string): string {
  const entry = SEVERITY_PRESENTATION[severity as PresentationSeverity];
  return entry?.className ?? SEVERITY_PRESENTATION.UNKNOWN.className;
}

export function severityLabel(severity: string): string {
  const entry = SEVERITY_PRESENTATION[severity as PresentationSeverity];
  return entry?.label ?? severity;
}
