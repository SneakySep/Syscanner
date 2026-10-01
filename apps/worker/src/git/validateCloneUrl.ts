/**
 * Clone-URL validation.
 *
 * A repository URL reaches git as an argv element. Left unchecked, three distinct
 * problems follow:
 *
 *  1. **Argument injection.** A value beginning with `-` is interpreted by git as a
 *     flag, so `--upload-pack=./evil` or `-u./evil` turns a "clone" into remote code
 *     execution on the worker host. A space, newline or NUL can smuggle extra argv
 *     elements through any wrapper that re-splits a string.
 *  2. **Protocol abuse.** `file:` reads the worker's own filesystem, `ext:` runs an
 *     arbitrary command, and `ssh:` reaches internal hosts with the worker's keys.
 *  3. **SSRF.** A URL aimed at `169.254.169.254` (cloud metadata), loopback or an
 *     RFC1918 address turns the worker into a proxy for the internal network.
 *
 * This function is deliberately allow-list based: exactly `https:`, a public host,
 * and a repository path. Everything else is refused.
 */

export class UnsafeCloneUrlError extends Error {
  public readonly code = 'UNSAFE_CLONE_URL';

  constructor(message: string) {
    super(message);
    this.name = 'UnsafeCloneUrlError';
  }
}

const ALLOWED_PROTOCOL = 'https:';
const MAX_URL_LENGTH = 2_048;

/** Names that resolve to the worker itself or to an internal/metadata service. */
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata',
  'metadata.google.internal',
  'instance-data',
  '169.254.169.254',
]);

function normalizeHost(hostname: string): string {
  // WHATWG URL keeps the brackets on IPv6 literals.
  return hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
}

function isBlockedIpv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;

  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;

  const a = octets[0] ?? 0;
  const b = octets[1] ?? 0;

  if (a === 0 || a === 10 || a === 127) return true; // this-network, private, loopback
  if (a === 169 && b === 254) return true; // link-local, includes cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a >= 224) return true; // multicast / reserved

  return false;
}

function isBlockedIpv6(host: string): boolean {
  const value = host.toLowerCase();

  if (value === '::1' || value === '::') return true;
  if (value.startsWith('fe80')) return true; // link-local
  if (value.startsWith('fc') || value.startsWith('fd')) return true; // unique local
  if (value.startsWith('::ffff:')) return isBlockedIpv4(value.slice('::ffff:'.length));

  return false;
}

/**
 * Validates a clone URL, returning its normalized form.
 *
 * @throws {UnsafeCloneUrlError} for anything that is not a plain public https URL.
 */
export function assertSafeCloneUrl(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new UnsafeCloneUrlError('Clone URL must be a string.');
  }

  const value = raw.trim();

  if (value.length === 0) {
    throw new UnsafeCloneUrlError('Clone URL must not be empty.');
  }

  if (value.length > MAX_URL_LENGTH) {
    throw new UnsafeCloneUrlError(`Clone URL exceeds ${MAX_URL_LENGTH} characters.`);
  }

  // Git flag injection. Checked before parsing so the diagnostic is explicit.
  if (value.startsWith('-')) {
    throw new UnsafeCloneUrlError(
      'Clone URL must not begin with "-": it would be parsed by git as an option.',
    );
  }

  // Whitespace or control characters can split into additional argv elements.
  if (/[\u0000-\u001f\u007f\s]/.test(value)) {
    throw new UnsafeCloneUrlError('Clone URL must not contain whitespace or control characters.');
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new UnsafeCloneUrlError(
      'Clone URL must be an absolute URL, e.g. https://github.com/acme/backend.git',
    );
  }

  if (parsed.protocol !== ALLOWED_PROTOCOL) {
    throw new UnsafeCloneUrlError(
      `Clone URL must use https:// (received "${parsed.protocol}"). ` +
        'file:, ssh:, git: and ext: are not permitted.',
    );
  }

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new UnsafeCloneUrlError(
      'Clone URL must not embed credentials; they would be written to .git/config and appear in logs.',
    );
  }

  if (parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new UnsafeCloneUrlError('Clone URL must not contain a query string or fragment.');
  }

  const host = normalizeHost(parsed.hostname);

  if (host.length === 0) {
    throw new UnsafeCloneUrlError('Clone URL must include a host.');
  }

  if (BLOCKED_HOSTNAMES.has(host)) {
    throw new UnsafeCloneUrlError(`Clone URL host "${host}" is not permitted.`);
  }

  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) {
    throw new UnsafeCloneUrlError(
      `Clone URL host "${host}" resolves to an internal network, which is not permitted.`,
    );
  }

  const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if ((isIpLiteral && isBlockedIpv4(host)) || (host.includes(':') && isBlockedIpv6(host))) {
    throw new UnsafeCloneUrlError(
      `Clone URL host "${host}" is a private, loopback or link-local address, which is not permitted.`,
    );
  }

  if (parsed.pathname.length <= 1) {
    throw new UnsafeCloneUrlError('Clone URL must include a repository path.');
  }

  return parsed.toString();
}
