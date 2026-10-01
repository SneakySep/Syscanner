import { describe, expect, it } from 'vitest';

import { computeFingerprint, computeInputFingerprint, hashSnippet } from './fingerprint';
import { evaluateQualityGate, isPathExcluded, parseScanPolicy } from './policy';
import { maskSecret, redactText } from './redaction';
import { resolveSeverity, severityFromCvss, tallySeverities } from './severity';

describe('computeFingerprint', () => {
  it('is stable for identical SAST input', () => {
    const input = {
      kind: 'SAST' as const,
      ruleId: 'rule.a',
      filePath: 'src/api/users.ts',
      startLine: 12,
      snippetHash: 'deadbeef',
    };
    expect(computeFingerprint(input)).toBe(computeFingerprint({ ...input }));
  });

  it('normalises Windows separators so fingerprints are portable', () => {
    const base = { kind: 'SAST' as const, ruleId: 'rule.a', startLine: 12 };
    expect(computeFingerprint({ ...base, filePath: 'src\\api\\users.ts' })).toBe(
      computeFingerprint({ ...base, filePath: 'src/api/users.ts' }),
    );
  });

  it('changes when the line number changes', () => {
    const base = { kind: 'SAST' as const, ruleId: 'rule.a', filePath: 'src/api/users.ts' };
    expect(computeFingerprint({ ...base, startLine: 12 })).not.toBe(
      computeFingerprint({ ...base, startLine: 13 }),
    );
  });

  it('identifies dependency findings by package rather than location', () => {
    const a = computeFingerprint({
      kind: 'DEPENDENCY',
      ruleId: 'CVE-2021-23337',
      ecosystem: 'npm',
      packageName: 'lodash',
    });
    const b = computeFingerprint({
      kind: 'DEPENDENCY',
      ruleId: 'CVE-2021-23337',
      ecosystem: 'npm',
      packageName: 'lodash',
      filePath: 'package-lock.json',
    });
    expect(a).toBe(b);
  });

  it('produces a 64-character sha256 hex digest', () => {
    expect(computeFingerprint({ kind: 'SECRETS', ruleId: 'aws-access-token' })).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });
});

describe('computeInputFingerprint', () => {
  it('is independent of tool-version key ordering', () => {
    const base = { repositoryId: 'repo_1', commitSha: 'abc', policyVersion: 1 };
    expect(
      computeInputFingerprint({ ...base, toolVersions: { semgrep: '1.90.0', trivy: '0.55.0' } }),
    ).toBe(
      computeInputFingerprint({ ...base, toolVersions: { trivy: '0.55.0', semgrep: '1.90.0' } }),
    );
  });
});

describe('severityFromCvss', () => {
  it.each([
    [9.8, 'CRITICAL'],
    [9.0, 'CRITICAL'],
    [7.5, 'HIGH'],
    [4.0, 'MEDIUM'],
    [0.1, 'LOW'],
  ] as const)('maps %s to %s', (score, expected) => {
    expect(severityFromCvss(score)).toBe(expected);
  });

  it('returns UNKNOWN rather than defaulting low when the score is missing', () => {
    expect(severityFromCvss(null)).toBe('UNKNOWN');
    expect(severityFromCvss(undefined)).toBe('UNKNOWN');
    expect(severityFromCvss(Number.NaN)).toBe('UNKNOWN');
  });
});

describe('resolveSeverity', () => {
  it('takes the more severe of tool and CVSS signals', () => {
    expect(resolveSeverity('LOW', 9.8)).toBe('CRITICAL');
    expect(resolveSeverity('CRITICAL', 2.0)).toBe('CRITICAL');
    expect(resolveSeverity('MEDIUM', 5.0)).toBe('MEDIUM');
  });
});

describe('tallySeverities', () => {
  it('counts each bucket and ignores UNKNOWN in gates', () => {
    const counts = tallySeverities(['CRITICAL', 'HIGH', 'HIGH', 'UNKNOWN', 'INFO']);
    expect(counts).toEqual({ critical: 1, high: 2, medium: 0, low: 0, info: 1 });
  });
});

describe('maskSecret / redactText', () => {
  it('never reveals a short secret', () => {
    expect(maskSecret('abc123')).toBe('******');
  });

  it('keeps only the first and last four characters', () => {
    // "AKIAIOSFODNN7EXAMPLE" is 20 characters: 4 visible + 12 masked + 4 visible.
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).toBe(`AKIA${'*'.repeat(12)}MPLE`);
  });

  it('redacts credentials embedded in arbitrary text', () => {
    const line = 'token = "ghp_' + 'a'.repeat(40) + '"';
    expect(redactText(line)).toBe('token = "[REDACTED]"');
  });
});

describe('isPathExcluded', () => {
  it('matches prefix globs', () => {
    expect(isPathExcluded('vendor/acme/lib.js', ['vendor/**'])).toBe(true);
    expect(isPathExcluded('src/app.ts', ['vendor/**'])).toBe(false);
  });

  it('matches suffix globs and exact paths', () => {
    expect(isPathExcluded('dist/bundle.min.js', ['**/*.min.js'])).toBe(true);
    // A leading "**/" must also match at the repository root.
    expect(isPathExcluded('bundle.min.js', ['**/*.min.js'])).toBe(true);
    expect(isPathExcluded('dist/app.js', ['**/*.min.js'])).toBe(false);
    expect(isPathExcluded('Dockerfile', ['Dockerfile'])).toBe(true);
  });
});

describe('evaluateQualityGate', () => {
  it('fails the gate when a finding meets the threshold', () => {
    expect(
      evaluateQualityGate({ critical: 0, high: 1, medium: 9, low: 0, info: 0 }, 'HIGH'),
    ).toEqual({ passed: false, blockingFindings: 1 });
  });

  it('passes when every finding is below the threshold', () => {
    expect(
      evaluateQualityGate({ critical: 0, high: 0, medium: 3, low: 4, info: 1 }, 'HIGH'),
    ).toEqual({ passed: true, blockingFindings: 0 });
  });
});

describe('parseScanPolicy', () => {
  it('falls back to safe defaults for malformed input', () => {
    expect(parseScanPolicy(null)).toEqual({
      scanners: ['SAST', 'SECRETS', 'DEPENDENCY'],
      excludePaths: [],
      failOn: 'HIGH',
    });
  });

  it('honours persisted overrides', () => {
    const policy = parseScanPolicy({ scanners: ['SECRETS'], failOn: 'CRITICAL' });
    expect(policy.scanners).toEqual(['SECRETS']);
    expect(policy.failOn).toBe('CRITICAL');
  });
});

describe('hashSnippet', () => {
  it('returns a sha256 digest and never the snippet itself', () => {
    const digest = hashSnippet('const password = "hunter2";');
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(digest).not.toContain('hunter2');
  });
});
