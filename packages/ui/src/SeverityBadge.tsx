import { cn } from './cn';
import { severityClassName, severityLabel } from './tokens';

export interface SeverityBadgeProps {
  severity: string;
  /** Optional count, rendered as "High 4" for summary rows. */
  count?: number;
  className?: string;
}

/**
 * Renders a severity chip. Presentation only — no logic about whether a finding
 * is blocking lives here.
 */
export function SeverityBadge({ severity, count, className }: SeverityBadgeProps) {
  return (
    <span
      role="status"
      aria-label={`Severity: ${severityLabel(severity)}`}
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold',
        severityClassName(severity),
        className,
      )}
    >
      {severityLabel(severity)}
      {typeof count === 'number' ? <span aria-hidden="true">{count}</span> : null}
    </span>
  );
}
