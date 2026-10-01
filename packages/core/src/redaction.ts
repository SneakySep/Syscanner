/**
 * Redaction helpers.
 *
 * Syscanner *detects* secrets, therefore it must never become the leak. Anything
 * that could echo a matched secret — logs, UI snippets, stored artifacts — passes
 * through here first.
 */

/** Patterns for the credential shapes we are most likely to encounter. */
const SECRET_PATTERNS: readonly RegExp[] = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub personal/app tokens
  /\bsk-[A-Za-z0-9]{20,}\b/g, // OpenAI-style API key
  /\bAIza[0-9A-Za-z\-_]{35}\b/g, // Google API key
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, // PEM private keys
];

export const REDACTED = '[REDACTED]';

/**
 * Unicode bidirectional and invisible formatting controls.
 *
 * These have no legitimate place in scanner output, and they are actively
 * dangerous in a code-shaped UI: a repository can use them to make a finding
 * *visually* read as something other than what it is (the "trojan source" class of
 * attack). A reviewer looking at a rendered line cannot see them at all.
 *
 *   U+202A..U+202E  LRE RLE PDF LRO RLO
 *   U+2066..U+2069  LRI RLI FSI PDI
 *   U+200E/U+200F    LRM RLM
 *   U+061C           ALM
 */
const BIDI_CONTROL_CHARS = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/g;

/** Removes bidi override controls so rendered text cannot contradict its bytes. */
export function stripBidiControls(input: string): string {
  return input.replace(BIDI_CONTROL_CHARS, '');
}

/** Replaces every recognised secret shape in arbitrary text. */
export function redactText(input: string, replacement: string = REDACTED): string {
  let output = stripBidiControls(input);
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output;
}

/**
 * Shows only enough of a value to be actionable: first and last four characters.
 * Short values are fully masked so we never reveal a whole credential.
 */
export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 8) return '*'.repeat(trimmed.length);
  const visible = 4;
  const maskedLength = Math.min(trimmed.length - visible * 2, 24);
  return `${trimmed.slice(0, visible)}${'*'.repeat(maskedLength)}${trimmed.slice(-visible)}`;
}

/**
 * Structured-logging serializer: walks a value and redacts any string that looks
 * like a credential, without mutating the original object.
 */
export function redactDeep<T>(value: T, depth = 0): T {
  if (depth > 8) return value;
  if (typeof value === 'string') return redactText(value) as unknown as T;
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, depth + 1)) as unknown as T;
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      result[key] = redactDeep(nested, depth + 1);
    }
    return result as unknown as T;
  }
  return value;
}
