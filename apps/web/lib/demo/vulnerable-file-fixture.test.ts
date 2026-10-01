import { describe, expect, it } from 'vitest';

import { buildDecorations, toPresentationSeverity } from '../../components/code-viewer/decorations';
import {
  FIXTURE_CODE,
  FIXTURE_FINDINGS,
  FIXTURE_LINE_COUNT,
} from './vulnerable-file-fixture';

/**
 * Guards the demo against silent drift.
 *
 * The fixture points findings at hardcoded line numbers, so an edit that adds or
 * removes a line would otherwise make the demo highlight the wrong code while still
 * looking like it works — the worst kind of failure for a demo.
 */
describe('vulnerable-file fixture', () => {
  it('has as many lines as it claims', () => {
    expect(FIXTURE_CODE.split('\n')).toHaveLength(FIXTURE_LINE_COUNT);
  });

  it('covers all four real severities, so the palette is exercised', () => {
    const severities = new Set(FIXTURE_FINDINGS.map((finding) => finding.severity));
    expect(severities).toEqual(new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']));
  });

  it('uses only known severities', () => {
    for (const finding of FIXTURE_FINDINGS) {
      expect(toPresentationSeverity(finding.severity)).toBe(finding.severity);
    }
  });

  it('gives every finding a title and a suggested fix', () => {
    for (const finding of FIXTURE_FINDINGS) {
      expect(finding.title.length).toBeGreaterThan(0);
      expect(finding.suggestedFix?.length ?? 0).toBeGreaterThan(0);
    }
  });

  it('points every in-range finding at a non-empty line', () => {
    const lines = FIXTURE_CODE.split('\n');

    for (const finding of FIXTURE_FINDINGS) {
      if (finding.line > FIXTURE_LINE_COUNT) continue; // the deliberate clamping case
      const content = lines[finding.line - 1];
      expect(content, `line ${String(finding.line)} should exist`).toBeDefined();
      expect(content?.trim().length ?? 0).toBeGreaterThan(0);
    }
  });

  it('keeps the two SQL injection lines adjacent and both populated', () => {
    const lines = FIXTURE_CODE.split('\n');
    const sqli = FIXTURE_FINDINGS.find((finding) => finding.id === 'fixture-sqli');
    expect(sqli?.line).toBe(15);
    expect(sqli?.endLine).toBe(16);
    expect(lines[14]).toContain('SELECT * FROM reports');
    expect(lines[15]).toContain('db.query');
  });

  it('points the secrets findings at the lines that actually contain the credentials', () => {
    const lines = FIXTURE_CODE.split('\n');
    expect(lines[7]).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(lines[8]).toContain('wJalrXUtnFEMI');
  });

  it('reports the deliberate out-of-range finding as clamped rather than dropping it', () => {
    const result = buildDecorations(FIXTURE_FINDINGS, FIXTURE_LINE_COUNT);
    const clampedIds = result.clamped.map((finding) => finding.id);
    expect(clampedIds).toContain('fixture-out-of-range');
    // Everything else must be placeable, or the demo is hiding findings.
    expect(result.skipped).toHaveLength(0);
    expect(result.decorations).toHaveLength(FIXTURE_FINDINGS.length);
  });
});