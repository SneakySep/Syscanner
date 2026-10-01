/**
 * Minimal class-name joiner. Avoids pulling a dependency into every app bundle
 * for what is fundamentally a one-line operation.
 */
export function cn(...values: Array<string | false | null | undefined>): string {
  return values.filter((value): value is string => Boolean(value)).join(' ');
}
