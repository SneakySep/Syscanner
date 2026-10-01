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

/** Replaces every recognised secret shape in arbitrary text. */
export function redactText(input: string, replacement: string = REDACTED): string {
  let output = input;
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output;
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
