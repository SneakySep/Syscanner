import { describe, expect, it } from 'vitest';

import {
  buildDecorations,
  clampFindingToDocument,
  DECORATION_CLASSES,
  DECORATION_GLYPH_CLASSES,
  lineForFinding,
  MAX_DECORATIONS,
  severityCounts,
  severityRank,
  sortFindings,
  toPresentationSeverity,
  type ViewerFinding,
} from './decorations';

function finding(overrides: Partial<ViewerFinding> = {}): ViewerFinding {
  return {
    id: 'f1',
    severity: 'HIGH',
    line: 10,
    title: 'Test finding',
    ...overrides,
  };
}

const CODE_LINES = 50;

describe('toPresentationSeverity', () => {
  it.each(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'])(
    'passes through the known severity %s',
    (severity) => {
      expect(toPresentationSeverity(severity)).toBe(severity);
    },
  );

  it.each(['', 'SEVERE', 'critical', 'HIGH '])(
    'maps the unrecognised severity %j onto UNKNOWN rather than leaving styling empty',
    (severity) => {
      expect(toPresentationSeverity(severity)).toBe('UNKNOWN');
    },
  );

  it('does not treat inherited object properties as severities', () => {
    // Guards the hasOwnProperty check: 'constructor' would otherwise index the map.
    expect(toPresentationSeverity('constructor')).toBe('UNKNOWN');
    expect(toPresentationSeverity('toString')).toBe('UNKNOWN');
  });
});

describe('severityRank', () => {
  it('orders critical before high before medium', () => {
    expect(severityRank('CRITICAL')).toBeLessThan(severityRank('HIGH'));
    expect(severityRank('HIGH')).toBeLessThan(severityRank('MEDIUM'));
    expect(severityRank('MEDIUM')).toBeLessThan(severityRank('LOW'));
  });

  it('ranks an unknown severity last, so it never outranks a real one', () => {
    expect(severityRank('nonsense')).toBeGreaterThan(severityRank('INFO'));
  });
});

describe('sortFindings', () => {
  it('sorts by severity, then line, then id', () => {
    const sorted = sortFindings([
      finding({ id: 'd', severity: 'LOW', line: 5 }),
      finding({ id: 'b', severity: 'CRITICAL', line: 30 }),
      finding({ id: 'a', severity: 'CRITICAL', line: 10 }),
      finding({ id: 'c', severity: 'MEDIUM', line: 1 }),
    ]);

    expect(sorted.map((item) => item.id)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('breaks ties on the same line by id, so order never depends on input order', () => {
    const forward = sortFindings([
      finding({ id: 'z', severity: 'HIGH', line: 10 }),
      finding({ id: 'a', severity: 'HIGH', line: 10 }),
    ]);
    const reversed = sortFindings([
      finding({ id: 'a', severity: 'HIGH', line: 10 }),
      finding({ id: 'z', severity: 'HIGH', line: 10 }),
    ]);

    expect(forward.map((item) => item.id)).toEqual(['a', 'z']);
    expect(reversed.map((item) => item.id)).toEqual(['a', 'z']);
  });

  it('does not mutate the input array', () => {
    const input = [finding({ id: 'b', line: 2 }), finding({ id: 'a', line: 1 })];
    const snapshot = input.map((item) => item.id);
    sortFindings(input);
    expect(input.map((item) => item.id)).toEqual(snapshot);
  });
});

describe('severityCounts', () => {
  it('counts each severity present', () => {
    expect(
      severityCounts([
        finding({ severity: 'CRITICAL' }),
        finding({ severity: 'HIGH' }),
        finding({ severity: 'HIGH' }),
      ]),
    ).toEqual({ CRITICAL: 1, HIGH: 2 });
  });

  it('returns an empty object for no findings', () => {
    expect(severityCounts([])).toEqual({});
  });
});

describe('clampFindingToDocument', () => {
  it('keeps a range that is already inside the document', () => {
    expect(clampFindingToDocument(finding({ line: 10, endLine: 12 }), CODE_LINES)).toEqual({
      startLineNumber: 10,
      endLineNumber: 12,
      clamped: false,
    });
  });

  it('anchors a line past the end instead of producing an invalid range', () => {
    const result = clampFindingToDocument(finding({ line: 9_999, endLine: 9_999 }), CODE_LINES);
    expect(result).toEqual({
      startLineNumber: CODE_LINES,
      endLineNumber: CODE_LINES,
      clamped: true,
    });
  });

  it('clamps line 0 and negatives up to line 1', () => {
    expect(clampFindingToDocument(finding({ line: 0 }), CODE_LINES)?.startLineNumber).toBe(1);
    expect(clampFindingToDocument(finding({ line: -5 }), CODE_LINES)?.startLineNumber).toBe(1);
  });

  it('never lets the end line precede the start line', () => {
    const result = clampFindingToDocument(finding({ line: 20, endLine: 5 }), CODE_LINES);
    expect(result?.startLineNumber).toBe(20);
    expect(result?.endLineNumber).toBe(20);
  });

  it('treats a missing end line as a single-line finding', () => {
    expect(clampFindingToDocument(finding({ line: 7 }), CODE_LINES)).toEqual({
      startLineNumber: 7,
      endLineNumber: 7,
      clamped: false,
    });
  });

  it('gives up on a non-numeric line rather than inventing a position', () => {
    expect(clampFindingToDocument(finding({ line: Number.NaN }), CODE_LINES)).toBeUndefined();
    expect(
      clampFindingToDocument(finding({ line: Number.POSITIVE_INFINITY }), CODE_LINES),
    ).toBeUndefined();
  });

  it('gives up on an empty document', () => {
    expect(clampFindingToDocument(finding({ line: 1 }), 0)).toBeUndefined();
  });

  it('truncates a fractional line number', () => {
    expect(clampFindingToDocument(finding({ line: 12.7 }), CODE_LINES)?.startLineNumber).toBe(12);
  });
});

describe('buildDecorations', () => {
  it('builds one whole-line decoration per placeable finding', () => {
    const result = buildDecorations(
      [
        finding({ id: 'sql', severity: 'CRITICAL', line: 24 }),
        finding({ id: 'key', severity: 'MEDIUM', line: 7 }),
      ],
      CODE_LINES,
    );

    expect(result.decorations).toHaveLength(2);
    expect(result.decorations.every((entry) => entry.options.isWholeLine)).toBe(true);
    // Most severe first: the sidebar and the decorations share one ordering.
    expect(result.decorations.map((entry) => entry.findingId)).toEqual(['sql', 'key']);
  });

  it('applies the severity class, drawn from a literal so Tailwind emits it', () => {
    const result = buildDecorations([finding({ severity: 'CRITICAL', line: 3 })], CODE_LINES);
    expect(result.decorations[0]!.options.className).toBe(DECORATION_CLASSES.CRITICAL);
    expect(result.decorations[0]!.options.glyphMarginClassName).toBe(
      DECORATION_GLYPH_CLASSES.CRITICAL,
    );
  });

  it('styles an unknown severity as UNKNOWN rather than leaving the class empty', () => {
    const result = buildDecorations([finding({ severity: 'SEVERE', line: 3 })], CODE_LINES);
    expect(result.decorations[0]!.options.className).toBe(DECORATION_CLASSES.UNKNOWN);
  });

  it('never emits a range outside the document', () => {
    const result = buildDecorations([finding({ line: 9_999, endLine: 12_000 })], CODE_LINES);

    const range = result.decorations[0]!.range;
    expect(range.startLineNumber).toBeLessThanOrEqual(CODE_LINES);
    expect(range.endLineNumber).toBeLessThanOrEqual(CODE_LINES);
    expect(result.clamped).toHaveLength(1);
  });

  it('reports rather than hides findings it could not place', () => {
    const result = buildDecorations([finding({ id: 'bad', line: Number.NaN })], CODE_LINES);
    expect(result.decorations).toHaveLength(0);
    expect(result.skipped.map((item) => item.id)).toEqual(['bad']);
  });

  it('caps the decoration count and reports the truncation', () => {
    const many = Array.from({ length: 25 }, (_value, index) =>
      finding({ id: `f${String(index)}`, line: index + 1 }),
    );

    const result = buildDecorations(many, CODE_LINES, 10);
    expect(result.decorations).toHaveLength(10);
    expect(result.truncated).toBe(true);
  });

  it('does not flag truncation when everything fits', () => {
    expect(buildDecorations([finding({ line: 1 })], CODE_LINES).truncated).toBe(false);
  });

  it('includes the suggested fix in the hover text', () => {
    const result = buildDecorations(
      [finding({ line: 1, title: 'SQL injection', suggestedFix: 'Use a parameterised query' })],
      CODE_LINES,
    );

    const hover = result.decorations[0]!.options.hoverMessage.value;
    expect(hover).toContain('SQL injection');
    expect(hover).toContain('Use a parameterised query');
  });

  it('falls back to the title alone when there is no suggested fix', () => {
    const result = buildDecorations([finding({ line: 1, title: 'Only a title' })], CODE_LINES);
    expect(result.decorations[0]!.options.hoverMessage.value).toBe('Only a title');
  });

  it('handles an empty document without throwing', () => {
    const result = buildDecorations([finding({ line: 1 })], 0);
    expect(result.decorations).toHaveLength(0);
    expect(result.skipped).toHaveLength(1);
  });

  it('returns nothing for no findings', () => {
    expect(buildDecorations([], CODE_LINES).decorations).toEqual([]);
  });

  it('exposes a decoration cap large enough for real scans', () => {
    expect(MAX_DECORATIONS).toBeGreaterThanOrEqual(1_000);
  });
});

describe('lineForFinding', () => {
  it('returns the clamped line to reveal', () => {
    expect(lineForFinding(finding({ line: 9_999 }), CODE_LINES)).toBe(CODE_LINES);
  });

  it('returns undefined when there is nothing to reveal', () => {
    expect(lineForFinding(undefined, CODE_LINES)).toBeUndefined();
    expect(lineForFinding(finding({ line: 1 }), 0)).toBeUndefined();
  });
});