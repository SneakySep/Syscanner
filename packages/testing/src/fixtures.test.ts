import { describe, expect, it } from 'vitest';

import { assertContainment, fixtureById, MALICIOUS_FIXTURES } from './fixtures';
import { makeFindings, makeSarifDocument } from './index';
import { parseSarif } from '@syscanner/scanners';

describe('malicious fixture corpus', () => {
  it('covers every threat that the sandbox is responsible for containing', () => {
    const covered = new Set(MALICIOUS_FIXTURES.flatMap((fixture) => fixture.threatIds));
    for (const expected of ['T2', 'T3', 'T5', 'T7', 'T8', 'T9', 'T11']) {
      expect(covered).toContain(expected);
    }
  });

  it('requires zero network egress from every fixture', () => {
    for (const fixture of MALICIOUS_FIXTURES) {
      expect(fixture.expectation.maxEgressBytes).toBe(0);
    }
  });

  it('flags a sandbox that allowed egress', () => {
    const fixture = fixtureById('postinstall-exfil')!;
    const verdict = assertContainment(fixture, {
      egressBytes: 1,
      peakMemoryMb: 100,
      wallClockMs: 1_000,
      peakPids: 5,
      wroteOutsideWorkdir: false,
    });
    expect(verdict.passed).toBe(false);
    expect(verdict.violations.join(' ')).toContain('egress');
  });

  it('passes a correctly contained run', () => {
    const fixture = fixtureById('fork-bomb')!;
    expect(
      assertContainment(fixture, {
        egressBytes: 0,
        peakMemoryMb: 512,
        wallClockMs: 30_000,
        peakPids: 200,
        wroteOutsideWorkdir: false,
      }).passed,
    ).toBe(true);
  });
});

describe('mock scanners', () => {
  it('produces deterministic findings', () => {
    const findings = makeFindings({ scanner: 'gitleaks', count: 3, severity: 'MEDIUM' });
    expect(findings).toHaveLength(3);
    expect(findings[0]!.scanner).toBe('gitleaks');
    expect(findings[0]!.severity).toBe('MEDIUM');
  });

  it('round-trips through the hardened SARIF parser', () => {
    const document = makeSarifDocument([
      { ruleId: 'r1', level: 'error', message: { text: 'boom' } },
    ]);
    const parsed = parseSarif(document, { scanner: 'mock', kind: 'SAST' });
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.title).toBe('boom');
  });
});
