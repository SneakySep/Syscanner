import { mkdtemp, rm, utimes, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ScratchConfig } from './scratch';

/**
 * One test below deliberately provokes a filesystem error to prove that cleanup
 * never throws. The scratch logger is created when its module is first evaluated,
 * so the level has to be set before the dynamic import that follows, otherwise the
 * expected warning floods the suite output.
 */
process.env.LOG_LEVEL = 'silent';

const {
  cleanupScanScratch,
  prepareScanScratch,
  scanScratchPaths,
  scanScratchRoot,
  sweepStaleScratch,
} = await import('./scratch');

let base = '';
const config = (): ScratchConfig => ({ WORKER_SCRATCH_DIR: base });

beforeEach(async () => {
  base = await mkdtemp(join(tmpdir(), 'syscanner-scratch-'));
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
});

describe('scanScratchRoot', () => {
  it('resolves a safe scan id beneath the configured scratch root', () => {
    expect(scanScratchRoot(config(), 'scan_abc-123')).toBe(join(resolve(base), 'scan_abc-123'));
  });

  it.each(['../escape', '..', 'a/b', 'a\\b', '', 'x'.repeat(65)])(
    'rejects the unsafe scan id %j rather than building a path from it',
    (scanId) => {
      expect(() => scanScratchRoot(config(), scanId)).toThrow(/unsafe scan id/);
    },
  );
});

describe('scanScratchPaths', () => {
  it('places the read-only source and the writable output side by side', () => {
    const paths = scanScratchPaths(config(), 'scan_1');
    expect(paths.sourceDir).toBe(join(resolve(base), 'scan_1', 'src'));
    expect(paths.outputDir).toBe(join(resolve(base), 'scan_1', 'out'));
  });
});

describe('prepareScanScratch', () => {
  it('creates the source and output directories', async () => {
    const paths = await prepareScanScratch(config(), 'scan_1');
    expect(existsSync(paths.sourceDir)).toBe(true);
    expect(existsSync(paths.outputDir)).toBe(true);
  });

  it('wipes a leftover tree so a retry never inherits a stale checkout', async () => {
    const first = await prepareScanScratch(config(), 'scan_1');
    await writeFile(join(first.sourceDir, 'stale.ts'), 'left over from the previous attempt');

    const second = await prepareScanScratch(config(), 'scan_1');
    expect(existsSync(join(second.sourceDir, 'stale.ts'))).toBe(false);
    // The directory itself must still exist, ready to be fetched into.
    expect(existsSync(second.sourceDir)).toBe(true);
  });
});

describe('cleanupScanScratch', () => {
  it('removes the whole tree', async () => {
    const paths = await prepareScanScratch(config(), 'scan_1');
    await writeFile(join(paths.sourceDir, 'index.ts'), 'export const x = 1;');

    await expect(cleanupScanScratch(config(), 'scan_1')).resolves.toBe(true);
    expect(existsSync(paths.root)).toBe(false);
  });

  it('succeeds when the tree is already gone, so cleanup is safe to call twice', async () => {
    await expect(cleanupScanScratch(config(), 'never_created')).resolves.toBe(true);
  });

  it('never throws, because a cleanup failure must not fail a completed scan', async () => {
    // A path that can never be a directory: cleanup must degrade, not reject.
    const hostile: ScratchConfig = { WORKER_SCRATCH_DIR: '\u0000invalid' };
    await expect(cleanupScanScratch(hostile, 'scan_1')).resolves.toBe(false);
  });

  it('leaves sibling scans untouched', async () => {
    await prepareScanScratch(config(), 'scan_1');
    await prepareScanScratch(config(), 'scan_2');

    await cleanupScanScratch(config(), 'scan_1');

    expect(existsSync(scanScratchPaths(config(), 'scan_1').root)).toBe(false);
    expect(existsSync(scanScratchPaths(config(), 'scan_2').root)).toBe(true);
  });
});

describe('sweepStaleScratch', () => {
  it('returns zero when the scratch root does not exist yet', async () => {
    await expect(sweepStaleScratch({ WORKER_SCRATCH_DIR: join(base, 'absent') }, 1)).resolves.toBe(
      0,
    );
  });

  it('removes only trees older than the cutoff, so an in-flight scan survives', async () => {
    const stale = await prepareScanScratch(config(), 'scan_stale');
    const active = await prepareScanScratch(config(), 'scan_active');

    // Age the stale tree by two hours.
    const twoHoursAgo = Date.now() / 1000 - 7_200;
    await utimes(stale.root, twoHoursAgo, twoHoursAgo);

    const removed = await sweepStaleScratch(config(), 3_600_000);

    expect(removed).toBe(1);
    expect(existsSync(stale.root)).toBe(false);
    expect(existsSync(active.root)).toBe(true);
  });

  it('ignores entries that are not safely named scan directories', async () => {
    await writeFile(join(base, 'not-a-scan-dir.txt'), 'ignore me');
    await expect(sweepStaleScratch(config(), 0)).resolves.toBe(0);
  });
});
