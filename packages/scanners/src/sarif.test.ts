import { describe, expect, it } from 'vitest';

import { parseSarif } from './sarif';
import { buildGitleaksInvocation, buildOsvScannerInvocation, buildSemgrepInvocation } from './tools';

function sarifDocument(results: unknown[], rules: unknown[] = []): string {
  return JSON.stringify({
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'test', rules } }, results }],
  });
}

describe('parseSarif', () => {
  it('extracts file path, line numbers and a snippet hash', () => {
    const result = parseSarif(
      sarifDocument([
        {
          ruleId: 'js/sql-injection',
          level: 'error',
          message: { text: 'SQL injection' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: './src/db/query.ts' },
                region: {
                  startLine: 118,
                  endLine: 124,
                  startColumn: 5,
                  endColumn: 44,
                  snippet: { text: 'db.query("SELECT " + id)' },
                },
              },
            },
          ],
        },
      ]),
      { scanner: 'semgrep', kind: 'SAST' },
    );

    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0]!;
    expect(finding.filePath).toBe('src/db/query.ts');
    expect(finding.startLine).toBe(118);
    expect(finding.endLine).toBe(124);
    expect(finding.severity).toBe('HIGH');
    // The snippet itself must never survive parsing.
    expect(finding.snippetHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(finding)).not.toContain('SELECT');
  });

  it('extracts CVE, CWE and GHSA identifiers from rule metadata and messages', () => {
    const result = parseSarif(
      sarifDocument(
        [
          {
            ruleId: 'GHSA-35jh-r3h4-6jhm',
            level: 'warning',
            message: { text: 'lodash is vulnerable to CVE-2021-23337' },
            properties: { tags: ['CWE-1321', 'security'] },
          },
        ],
        [
          {
            id: 'GHSA-35jh-r3h4-6jhm',
            properties: { tags: ['CWE-1321'] },
            helpUri: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm',
          },
        ],
      ),
      { scanner: 'osv-scanner', kind: 'DEPENDENCY' },
    );

    const finding = result.findings[0]!;
    expect(finding.cveIds).toEqual(['CVE-2021-23337']);
    expect(finding.cweIds).toContain('CWE-1321');
    expect(finding.ghsaId).toBe('GHSA-35jh-r3h4-6jhm');
  });

  it('maps SARIF levels to severities', () => {
    const parse = (level: string) =>
      parseSarif(sarifDocument([{ ruleId: 'r', level, message: { text: 'm' } }]), {
        scanner: 'semgrep',
        kind: 'SAST',
      }).findings[0]!.severity;

    expect(parse('error')).toBe('HIGH');
    expect(parse('warning')).toBe('MEDIUM');
    expect(parse('note')).toBe('LOW');
    expect(parse('none')).toBe('INFO');
  });

  it('lets a reported CVSS score override a lower tool level', () => {
    const result = parseSarif(
      sarifDocument([
        {
          ruleId: 'r',
          level: 'warning',
          message: { text: 'm' },
          properties: { 'security-severity': '9.8' },
        },
      ]),
      { scanner: 'semgrep', kind: 'SAST' },
    );
    expect(result.findings[0]!.severity).toBe('CRITICAL');
  });

  it('strips control characters from hostile messages', () => {
    const result = parseSarif(
      sarifDocument([{ ruleId: 'r', level: 'note', message: { text: 'evil\u001b[31m\u0007text' } }]),
      { scanner: 'semgrep', kind: 'SAST' },
    );
    expect(result.findings[0]!.title).toBe('evil[31mtext');
  });

  it('strips bidi overrides that would make a finding read as something else', () => {
    // Without this, "deploy\u202epayload" renders so a reviewer sees the reverse of
    // what the bytes say — dangerous in the code viewer, where findings sit beside
    // the source they describe.
    const result = parseSarif(
      sarifDocument([
        { ruleId: 'r\u202e', level: 'error', message: { text: 'safe\u202eevil\u2066text' } },
      ]),
      { scanner: 'semgrep', kind: 'SAST' },
    );

    const finding = result.findings[0]!;
    expect(finding.title).toBe('safeeviltext');
    expect(finding.ruleId).toBe('r');
    expect(JSON.stringify(finding)).not.toMatch(/[\u202a-\u202e\u2066-\u2069]/);
  });

  it('degrades gracefully on malformed JSON instead of throwing', () => {
    const result = parseSarif('{not json', { scanner: 'semgrep', kind: 'SAST' });
    expect(result.findings).toEqual([]);
    expect(result.warnings[0]).toContain('not valid JSON');
  });

  it('rejects artifacts above the size cap', () => {
    const result = parseSarif(sarifDocument([{ ruleId: 'r' }]), {
      scanner: 'semgrep',
      kind: 'SAST',
      maxBytes: 10,
    });
    expect(result.truncated).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('caps the number of results and reports truncation', () => {
    const results = Array.from({ length: 25 }, (_value, index) => ({
      ruleId: `rule-${index}`,
      level: 'note',
      message: { text: 'm' },
    }));

    const parsed = parseSarif(sarifDocument(results), {
      scanner: 'semgrep',
      kind: 'SAST',
      maxResults: 10,
    });

    expect(parsed.findings).toHaveLength(10);
    expect(parsed.truncated).toBe(true);
  });
});

describe('tool adapters', () => {
  const target = { sourceDir: '/work/src', reportPath: '/work/out/report.sarif' };

  it('never spreads ambient environment variables into the sandbox', () => {
    process.env.LEAKED_SECRET = 'super-secret';
    const invocation = buildSemgrepInvocation(target);
    expect(Object.values(invocation.env)).not.toContain('super-secret');
    expect(invocation.env).not.toHaveProperty('LEAKED_SECRET');
    delete process.env.LEAKED_SECRET;
  });

  it('pins semgrep to a local trusted ruleset and disables telemetry', () => {
    const { argv } = buildSemgrepInvocation(target);
    const configIndex = argv.indexOf('--config');
    expect(argv[configIndex + 1]).toBe('/opt/syscanner/rules/semgrep');
    expect(argv[configIndex + 1]).not.toMatch(/^https?:/);
    expect(argv).toContain('--metrics=off');
    expect(argv).toContain('--disable-version-check');
  });

  it('asks gitleaks to redact matches', () => {
    expect(buildGitleaksInvocation(target).argv).toContain('--redact');
  });

  it('runs dependency scanning fully offline', () => {
    expect(buildOsvScannerInvocation(target).argv).toContain('--offline');
  });
});
