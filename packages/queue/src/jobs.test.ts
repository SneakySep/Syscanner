import { describe, expect, it } from 'vitest';

import {
  CONSUMER_QUEUES,
  parseJobPayload,
  QUEUE_NAMES,
  scanRepositoryJobSchema,
  scannerJobSchema,
} from './index';

const base = {
  jobId: 'scan_1',
  repositoryUrl: 'https://github.com/acme/backend.git',
  commitSha: 'f3a91c7d2b8e45016cd9a0f17e2b3c4d5e6f7a8b',
};

describe('queue topology', () => {
  it('consumes the repository queue alongside the existing pipeline', () => {
    expect(CONSUMER_QUEUES).toContain(QUEUE_NAMES.repository);
    expect(QUEUE_NAMES.repository).toBe('scan:repository');
  });
});

describe('scanRepositoryJobSchema', () => {
  it('accepts a well-formed standalone job', () => {
    const parsed = parseJobPayload(scanRepositoryJobSchema, base, QUEUE_NAMES.repository);

    expect(parsed.jobId).toBe('scan_1');
    expect(parsed.commitSha).toBe(base.commitSha);
    // A standalone job must not require tenant fields — that is the whole point.
    expect(parsed.organizationId).toBeUndefined();
    expect(parsed.repositoryId).toBeUndefined();
  });

  it.each(['a:b', 'a/b', 'a\\b', '../escape', '..', '', 'x'.repeat(65)])(
    'rejects the unsafe jobId %j, because it becomes a scratch directory name',
    (jobId) => {
      expect(() =>
        parseJobPayload(scanRepositoryJobSchema, { ...base, jobId }, QUEUE_NAMES.repository),
      ).toThrow(/jobId/);
    },
  );

  it('rejects a branch name where a commit SHA is required', () => {
    expect(() =>
      parseJobPayload(
        scanRepositoryJobSchema,
        { ...base, commitSha: 'main' },
        QUEUE_NAMES.repository,
      ),
    ).toThrow(/commitSha/);
  });

  it('rejects a missing repository URL', () => {
    expect(() =>
      parseJobPayload(scanRepositoryJobSchema, { ...base, repositoryUrl: '' }, QUEUE_NAMES.repository),
    ).toThrow(/repositoryUrl/);
  });

  it('accepts an optional trusted ruleset path override', () => {
    const parsed = parseJobPayload(
      scanRepositoryJobSchema,
      { ...base, semgrepConfigPath: '/opt/syscanner/rules/semgrep', ref: 'main' },
      QUEUE_NAMES.repository,
    );

    expect(parsed.semgrepConfigPath).toBe('/opt/syscanner/rules/semgrep');
    expect(parsed.ref).toBe('main');
  });
});

describe('scannerJobSchema', () => {
  it('applies the policyVersion default so processors always receive a number', () => {
    const parsed = parseJobPayload(
      scannerJobSchema,
      {
        scanId: 'scan_1',
        organizationId: 'org_1',
        repositoryId: 'repo_1',
        kind: 'SAST',
        tool: 'semgrep',
        commitSha: 'abcdef1',
        sourceKey: '/work/syscanner/scan_1/src',
      },
      QUEUE_NAMES.sast,
    );

    expect(parsed.policyVersion).toBe(1);
  });
});

describe('parseJobPayload', () => {
  it('names the queue and the offending field, so a bad job is diagnosable', () => {
    expect(() =>
      parseJobPayload(scannerJobSchema, { scanId: 'scan_1' }, QUEUE_NAMES.sast),
    ).toThrow(/Invalid scan:sast job payload/);
  });
});
