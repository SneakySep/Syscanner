import { describe, expect, it } from 'vitest';

import { assertSafeCloneUrl, UnsafeCloneUrlError } from './validateCloneUrl';

describe('assertSafeCloneUrl', () => {
  it('accepts a normal public https repository URL', () => {
    expect(assertSafeCloneUrl('https://github.com/acme/backend.git')).toBe(
      'https://github.com/acme/backend.git',
    );
  });

  it('accepts an explicit port for self-hosted instances', () => {
    expect(assertSafeCloneUrl('https://git.example.com:8443/acme/backend.git')).toBe(
      'https://git.example.com:8443/acme/backend.git',
    );
  });

  it('trims surrounding whitespace rather than treating it as injection', () => {
    expect(assertSafeCloneUrl('  https://github.com/acme/backend.git  ')).toBe(
      'https://github.com/acme/backend.git',
    );
  });

  // ── Argument injection (git parses a leading "-" as an option) ──────────────

  it.each([
    '--upload-pack=./evil',
    '-u./evil',
    '--config=core.hooksPath=/tmp/hooks',
    '--upload-pack /opt/evil',
  ])('rejects the git flag-injection payload %j', (payload) => {
    expect(() => assertSafeCloneUrl(payload)).toThrow(UnsafeCloneUrlError);
  });

  it('rejects embedded whitespace and control characters', () => {
    expect(() => assertSafeCloneUrl('https://github.com/a b/c.git')).toThrow(/whitespace/);
    expect(() => assertSafeCloneUrl('https://github.com/acme/back\nend.git')).toThrow(
      UnsafeCloneUrlError,
    );
    expect(() => assertSafeCloneUrl('https://github.com/acme/back\u0000end.git')).toThrow(
      UnsafeCloneUrlError,
    );
  });

  // ── Protocol abuse ─────────────────────────────────────────────────────────

  it.each([
    'file:///etc/passwd',
    'file://localhost/etc/shadow',
    'ssh://git@github.com/acme/backend.git',
    'git://github.com/acme/backend.git',
    'http://github.com/acme/backend.git',
    'ftp://github.com/acme/backend.git',
    'ext::sh -c curl%20evil',
  ])('rejects the non-https protocol in %j', (url) => {
    expect(() => assertSafeCloneUrl(url)).toThrow(UnsafeCloneUrlError);
  });

  it('rejects scp-style syntax, which is not an absolute URL', () => {
    expect(() => assertSafeCloneUrl('git@github.com:acme/backend.git')).toThrow(
      /absolute URL/,
    );
  });

  // ── Credential smuggling ───────────────────────────────────────────────────

  it('rejects credentials embedded in the URL', () => {
    expect(() => assertSafeCloneUrl('https://user:hunter2@github.com/acme/backend.git')).toThrow(
      /must not embed credentials/,
    );
  });

  it('rejects a query string or fragment', () => {
    expect(() => assertSafeCloneUrl('https://github.com/acme/backend.git?token=abc')).toThrow(
      /query string/,
    );
    expect(() => assertSafeCloneUrl('https://github.com/acme/backend.git#main')).toThrow(
      /query string/,
    );
  });

  // ── SSRF ───────────────────────────────────────────────────────────────────

  it.each([
    'https://169.254.169.254/latest/meta-data',
    'https://127.0.0.1/repo.git',
    'https://127.1/repo.git',
    'https://0.0.0.0/repo.git',
    'https://10.0.0.5/repo.git',
    'https://172.16.0.1/repo.git',
    'https://172.31.255.254/repo.git',
    'https://192.168.1.10/repo.git',
    'https://100.64.0.1/repo.git',
  ])('rejects the SSRF target %j', (url) => {
    expect(() => assertSafeCloneUrl(url)).toThrow(/not permitted/);
  });

  it('rejects an integer-encoded loopback address that the URL parser normalizes', () => {
    // https://2130706433/ is 127.0.0.1 in decimal form.
    expect(() => assertSafeCloneUrl('https://2130706433/repo.git')).toThrow(/not permitted/);
  });

  it.each([
    'https://[::1]/repo.git',
    'https://[fd00::1]/repo.git',
    'https://[fe80::1]/repo.git',
  ])('rejects the IPv6 SSRF target %j', (url) => {
    expect(() => assertSafeCloneUrl(url)).toThrow(/not permitted/);
  });

  it('rejects cloud metadata hostnames', () => {
    expect(() => assertSafeCloneUrl('https://169.254.169.254/repo.git')).toThrow(
      UnsafeCloneUrlError,
    );
    expect(() => assertSafeCloneUrl('https://metadata.google.internal/repo.git')).toThrow(
      /not permitted/,
    );
    expect(() => assertSafeCloneUrl('https://instance-data/repo.git')).toThrow(/not permitted/);
  });

  it.each(['https://localhost/repo.git', 'https://git.local/repo.git', 'https://git.internal/repo.git'])(
    'rejects the internal hostname %j',
    (url) => {
      expect(() => assertSafeCloneUrl(url)).toThrow(/not permitted|internal network/);
    },
  );

  // ── Shape and bounds ───────────────────────────────────────────────────────

  it.each(['', '   ', 'not a url', 'github.com/acme/backend'])(
    'rejects the malformed input %j',
    (url) => {
      expect(() => assertSafeCloneUrl(url)).toThrow(UnsafeCloneUrlError);
    },
  );

  it('rejects a URL with no repository path', () => {
    expect(() => assertSafeCloneUrl('https://github.com')).toThrow(/repository path/);
    expect(() => assertSafeCloneUrl('https://github.com/')).toThrow(/repository path/);
  });

  it('rejects non-string input', () => {
    expect(() => assertSafeCloneUrl(undefined)).toThrow(/must be a string/);
    expect(() => assertSafeCloneUrl(42)).toThrow(/must be a string/);
  });

  it('rejects an over-long URL', () => {
    expect(() => assertSafeCloneUrl(`https://github.com/acme/${'a'.repeat(3_000)}.git`)).toThrow(
      /exceeds/,
    );
  });
});
