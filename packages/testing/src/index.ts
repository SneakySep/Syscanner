import type { NormalizedFinding } from '@syscanner/scanners';

/**
 * Deterministic fakes for unit tests.
 *
 * A test that needs "the SECRETS scanner found an AWS key" must not depend on
 * Gitleaks being installed, on a network call, or on the current date. These
 * helpers produce that data directly.
 */

export interface MockScannerOptions {
  scanner: string;
  count?: number;
  severity?: NormalizedFinding['severity'];
  withCve?: boolean;
}

export function makeFinding(
  overrides: Partial<NormalizedFinding> = {},
): NormalizedFinding {
  return {
    kind: 'SAST',
    scanner: 'semgrep',
    ruleId: 'test.rule',
    title: 'Test finding',
    severity: 'HIGH',
    cweIds: [],
    cveIds: [],
    references: [],
    filePath: 'src/index.ts',
    startLine: 10,
    endLine: 12,
    ...overrides,
  };
}

export function makeFindings(options: MockScannerOptions): NormalizedFinding[] {
  const count = options.count ?? 1;
  return Array.from({ length: count }, (_value, index) =>
    makeFinding({
      scanner: options.scanner,
      ruleId: `${options.scanner}.rule.${index}`,
      title: `${options.scanner} finding ${index}`,
      severity: options.severity ?? 'HIGH',
      filePath: `src/module-${index}.ts`,
      startLine: 10 + index,
      endLine: 12 + index,
      ...(options.withCve
        ? { cveIds: [`CVE-2024-${1000 + index}`], kind: 'DEPENDENCY' as const }
        : {}),
    }),
  );
}

/** Minimal valid SARIF document wrapping the given results, for parser tests. */
export function makeSarifDocument(
  results: Array<Record<string, unknown>>,
): string {
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'mock', version: '0.0.0', rules: [] } }, results }],
  });
}
