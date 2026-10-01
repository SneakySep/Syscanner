import { createHash } from 'node:crypto';

import { normalizeRepoPath, resolveSeverity, stripBidiControls, type FindingKindName, type SeverityName } from '@syscanner/core';

import type { NormalizedFinding, ParseOptions, ParseResult, SarifLevel } from './types';

/**
 * Hardened SARIF ingestion.
 *
 * Everything in this file assumes the input is attacker-controlled. A repository
 * author can influence scanner output (rule ids, messages, file paths, snippets),
 * so we never spread raw objects into our own structures, never trust types, cap
 * both input size and result count, and strip control characters that could be
 * used for terminal or log injection.
 */

const DEFAULT_MAX_BYTES = 32 * 1024 * 1024; // 32 MiB
const DEFAULT_MAX_RESULTS = 10_000;
const MAX_STRING_LENGTH = 4_096;

const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
const CVE_PATTERN = /CVE-\d{4}-\d{4,}/gi;
const CWE_PATTERN = /CWE-\d{1,5}/gi;
const GHSA_PATTERN = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi;

const LEVEL_TO_SEVERITY: Record<SarifLevel, SeverityName> = {
  error: 'HIGH',
  warning: 'MEDIUM',
  note: 'LOW',
  none: 'INFO',
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Trims, strips control characters and hard-caps length. Returns undefined if empty.
 *
 * Bidi overrides are removed here as well as C0 controls: a repository can otherwise
 * make a finding render as something other than what its bytes say, which matters
 * most in the code viewer where findings sit next to the source they describe.
 */
function sanitizeString(value: unknown, maxLength = MAX_STRING_LENGTH): string | undefined {
  if (typeof value !== 'string') return undefined;
  const cleaned = stripBidiControls(value.replace(CONTROL_CHARS, '')).trim();
  if (cleaned.length === 0) return undefined;
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
}

function positiveInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
  return Math.trunc(value);
}

function finiteScore(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 10) {
    return value;
  }
  // Some tools emit the CVSS score as a string in SARIF properties.
  if (typeof value === 'string') {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 10) return parsed;
  }
  return undefined;
}

type Normalizer = (value: string) => string;

/** CVE and CWE identifiers are canonically upper case; GHSA ids are not. */
const toUpperCase: Normalizer = (value) => value.toUpperCase();
const asIs: Normalizer = (value) => value;

/**
 * Extracts unique identifier matches. The normalizer exists because CVE/CWE
 * identifiers must be canonicalised while GHSA identifiers keep their mixed
 * case (e.g. "GHSA-35jh-r3h4-6jhm").
 */
function collectMatches(text: string, pattern: RegExp, normalize: Normalizer = asIs): string[] {
  const found = text.match(pattern);
  if (!found) return [];
  return [...new Set(found.map((match) => normalize(match)))];
}

function hashSnippetText(text: string | undefined): string | undefined {
  if (!text) return undefined;
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function severityFor(level: unknown, securitySeverity: unknown, cvssScore: unknown): SeverityName {
  const toolSeverity =
    typeof level === 'string' && level in LEVEL_TO_SEVERITY
      ? LEVEL_TO_SEVERITY[level as SarifLevel]
      : undefined;

  const score = finiteScore(cvssScore) ?? finiteScore(securitySeverity);
  return resolveSeverity(toolSeverity, score);
}

function extractLocation(result: Record<string, unknown>): Partial<NormalizedFinding> {
  const locations = asArray(result.locations);
  const firstLocation = asRecord(locations[0]);
  if (!firstLocation) return {};

  const physical = asRecord(firstLocation.physicalLocation);
  if (!physical) return {};

  const uri = sanitizeString(asRecord(physical.artifactLocation)?.uri, 1_024);
  const region = asRecord(physical.region);
  const snippetText = region ? sanitizeString(asRecord(region.snippet)?.text, 8_192) : undefined;

  return {
    // Strip any leading "./" and normalise separators so fingerprints are portable.
    filePath: uri ? normalizeRepoPath(uri) : undefined,
    startLine: region ? positiveInt(region.startLine) : undefined,
    endLine: region ? positiveInt(region.endLine) : undefined,
    startColumn: region ? positiveInt(region.startColumn) : undefined,
    endColumn: region ? positiveInt(region.endColumn) : undefined,
    snippetHash: hashSnippetText(snippetText),
  };
}

interface RuleMetadata {
  cweIds: string[];
  tags: string[];
  helpUri?: string;
}

/** Builds a lookup of ruleId -> CWE ids / tags from the run's rule descriptors. */
function extractRuleMetadata(run: Record<string, unknown>): Map<string, RuleMetadata> {
  const index = new Map<string, RuleMetadata>();
  const tool = asRecord(run.tool);
  const driver = tool ? asRecord(tool.driver) : undefined;
  const rules = driver ? asArray(driver.rules) : [];

  for (const rule of rules) {
    const record = asRecord(rule);
    if (!record) continue;

    const id = sanitizeString(record.id, 512);
    if (!id) continue;

    const properties = asRecord(record.properties);
    const tags = asArray(properties?.tags)
      .map((tag) => sanitizeString(tag, 128))
      .filter((tag): tag is string => Boolean(tag));

    const cweSource = [tags.join(' '), sanitizeString(properties?.cwe, 128) ?? ''].join(' ');

    index.set(id, {
      cweIds: collectMatches(cweSource, CWE_PATTERN, toUpperCase),
      tags,
      helpUri: sanitizeString(record.helpUri, 1_024),
    });
  }

  return index;
}

/**
 * Parses a SARIF 2.1.0 document produced by any adapter.
 *
 * Never throws on malformed input: a hostile artifact should degrade to "no
 * findings + a warning", not crash the ingest pipeline.
 */
export function parseSarif(jsonText: string, options: ParseOptions): ParseResult {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxResults = options.maxResults ?? DEFAULT_MAX_RESULTS;
  const warnings: string[] = [];

  if (Buffer.byteLength(jsonText, 'utf8') > maxBytes) {
    return {
      findings: [],
      truncated: true,
      warnings: [`Artifact exceeds ${maxBytes} bytes and was rejected.`],
    };
  }

  let document: unknown;
  try {
    document = JSON.parse(jsonText);
  } catch {
    return { findings: [], truncated: false, warnings: ['Artifact is not valid JSON.'] };
  }

  const runs = asArray(asRecord(document)?.runs);
  if (runs.length === 0) {
    return { findings: [], truncated: false, warnings: ['SARIF document contains no runs.'] };
  }

  const findings: NormalizedFinding[] = [];
  let truncated = false;

  for (const run of runs) {
    const runRecord = asRecord(run);
    if (!runRecord) continue;

    const ruleIndex = extractRuleMetadata(runRecord);

    for (const rawResult of asArray(runRecord.results)) {
      if (findings.length >= maxResults) {
        truncated = true;
        warnings.push(`Result cap of ${maxResults} reached; remaining results discarded.`);
        break;
      }

      const result = asRecord(rawResult);
      if (!result) continue;

      const ruleId = sanitizeString(result.ruleId, 512) ?? 'unknown-rule';
      const properties = asRecord(result.properties);
      const metadata = ruleIndex.get(ruleId);
      const messageRecord = asRecord(result.message);

      const message =
        sanitizeString(messageRecord?.text) ??
        sanitizeString(messageRecord?.markdown) ??
        ruleId;

      const tags = asArray(properties?.tags)
        .map((tag) => sanitizeString(tag, 128))
        .filter((tag): tag is string => Boolean(tag));

      const combinedSignal = [
        ruleId,
        message,
        metadata?.tags.join(' ') ?? '',
        tags.join(' '),
      ].join(' ');

      const cveIds = collectMatches(combinedSignal, CVE_PATTERN, toUpperCase);

      findings.push({
        kind: options.kind,
        scanner: options.scanner,
        ruleId,
        title: message.length > 512 ? message.slice(0, 512) : message,
        description: sanitizeString(result.fullDescriptionText),
        category: tags[0] ?? metadata?.tags[0],
        severity: severityFor(
          result.level,
          properties?.['security-severity'],
          properties?.cvssScore,
        ),
        cvssScore:
          finiteScore(properties?.cvssScore) ?? finiteScore(properties?.['security-severity']),
        cvssVector: sanitizeString(properties?.cvssVector, 256),
        cweIds: [
          ...new Set([
            ...(metadata?.cweIds ?? []),
            ...collectMatches(combinedSignal, CWE_PATTERN, toUpperCase),
          ]),
        ],
        cveIds,
        ghsaId: collectMatches(combinedSignal, GHSA_PATTERN)[0],
        ...extractLocation(result),
        references: [
          ...new Set(
            [metadata?.helpUri, sanitizeString(properties?.helpUri, 1_024)].filter(
              (value): value is string => Boolean(value),
            ),
          ),
        ],
      });
    }

    if (truncated) break;
  }

  return { findings, truncated, warnings };
}

/** Convenience helper for a dependency/SCA result set. */
export function parseDependencySarif(jsonText: string, scanner: string): ParseResult {
  return parseSarif(jsonText, { scanner, kind: 'DEPENDENCY' });
}

/** Exposed for adapter tests. */
export const __internals = { sanitizeString, severityFor, LEVEL_TO_SEVERITY };
export type { FindingKindName };
