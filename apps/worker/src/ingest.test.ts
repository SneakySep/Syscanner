import { describe, expect, it } from 'vitest';

/**
 * `ingest.ts` pulls in the Prisma client, which validates its datasource when it is
 * constructed. Supply a syntactically valid URL so the mapping can be exercised
 * without a database — nothing here opens a connection. The env assignment must run
 * before the import, hence the dynamic import below.
 */
process.env.DATABASE_URL ??=
  'postgresql://syscanner:syscanner@localhost:5432/syscanner?schema=public';

const { fingerprintFor, toDatabasePayload } = await import('./ingest');

const semgrepFinding = {
  kind: 'SAST' as const,
  scanner: 'semgrep',
  ruleId: 'javascript.lang.security.audit.sqli.node-mysql-sqli',
  title: 'User input concatenated into a SQL query',
  description: 'Untrusted input reaches a query builder.',
  category: 'sql-injection',
  severity: 'CRITICAL' as const,
  cvssScore: 9.8,
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  cweIds: ['CWE-89'],
  cveIds: [],
  references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  filePath: 'src/db/legacy/reportQueries.ts',
  startLine: 118,
  endLine: 124,
  startColumn: 5,
  endColumn: 44,
  snippetHash: 'e'.repeat(64),
};

describe('toDatabasePayload', () => {
  it('maps a SAST finding onto the Finding columns', () => {
    const row = toDatabasePayload(semgrepFinding);

    expect(row.kind).toBe('SAST');
    expect(row.severity).toBe('CRITICAL');
    expect(row.ruleId).toBe(semgrepFinding.ruleId);
    expect(row.cweIds).toEqual(['CWE-89']);
    // Line-accurate location is a product requirement, not a detail.
    expect(row.filePath).toBe('src/db/legacy/reportQueries.ts');
    expect(row.startLine).toBe(118);
    expect(row.endLine).toBe(124);
    expect(row.startColumn).toBe(5);
    expect(row.endColumn).toBe(44);
  });

  it('serializes the CVSS score as a string, which is what Prisma Decimal accepts', () => {
    expect(toDatabasePayload(semgrepFinding).cvssScore).toBe('9.8');
  });

  it('maps a dependency finding, including the fixed version', () => {
    const row = toDatabasePayload({
      kind: 'DEPENDENCY',
      scanner: 'osv-scanner',
      ruleId: 'GHSA-35jh-r3h4-6jhm',
      title: 'lodash prototype pollution',
      severity: 'HIGH',
      cweIds: ['CWE-1321'],
      cveIds: ['CVE-2021-23337'],
      ghsaId: 'GHSA-35jh-r3h4-6jhm',
      packageName: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      ecosystem: 'npm',
      references: [],
    });

    expect(row.packageName).toBe('lodash');
    expect(row.fixedVersion).toBe('4.17.21');
    expect(row.cveIds).toEqual(['CVE-2021-23337']);
    // A dependency finding has no source location.
    expect(row.filePath).toBeNull();
    expect(row.startLine).toBeNull();
  });

  it('uses null rather than undefined for absent fields', () => {
    const row = toDatabasePayload({
      kind: 'SECRETS',
      scanner: 'gitleaks',
      ruleId: 'aws-access-token',
      title: 'Hardcoded AWS key',
      severity: 'MEDIUM',
      cweIds: [],
      cveIds: [],
      references: [],
    });

    // `undefined` would make Prisma fall back to a column default; explicit null is
    // what "this finding genuinely has no location" means.
    expect(row.filePath).toBeNull();
    expect(row.description).toBeNull();
    expect(row.category).toBeNull();
    expect(row.cvssScore).toBeNull();
    expect(row.ghsaId).toBeNull();
    expect(row.snippetHash).toBeNull();
  });

  it('never carries the snippet text, only its hash', () => {
    const row = toDatabasePayload(semgrepFinding);
    expect(JSON.stringify(row)).not.toContain('SELECT');
    expect(row.snippetHash).toBe('e'.repeat(64));
  });
});

describe('fingerprintFor', () => {
  it('is stable for the same issue', () => {
    expect(fingerprintFor(semgrepFinding)).toBe(fingerprintFor({ ...semgrepFinding }));
  });

  it('changes when the line number changes', () => {
    expect(fingerprintFor(semgrepFinding)).not.toBe(
      fingerprintFor({ ...semgrepFinding, startLine: 119 }),
    );
  });

  it('produces a sha256 hex digest', () => {
    expect(fingerprintFor(semgrepFinding)).toMatch(/^[0-9a-f]{64}$/);
  });
});
