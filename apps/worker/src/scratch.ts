import { mkdir, readdir, rm, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { createLogger } from '@syscanner/logger';

import type { WorkerConfig } from './config';

const logger = createLogger({ name: 'worker:scratch' });

/** The only field the scratch helpers need, so they are testable without full env. */
export type ScratchConfig = Pick<WorkerConfig, 'WORKER_SCRATCH_DIR'>;

export interface ScanScratch {
  root: string;
  sourceDir: string;
  outputDir: string;
}

/** cuids and our other ids are `[A-Za-z0-9_-]`; anything else is not ours. */
const SAFE_SCAN_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Guards against path traversal.
 *
 * Scan ids come from our own database, but a value containing `../` would turn the
 * cleanup `rm -rf` below into an arbitrary-directory delete. The invariant is
 * asserted rather than assumed, because the cost of being wrong here is unbounded.
 */
function assertSafeScanId(scanId: string): string {
  if (!SAFE_SCAN_ID.test(scanId)) {
    throw new Error(
      `Refusing to build a scratch path from an unsafe scan id: ${JSON.stringify(scanId)}`,
    );
  }
  return scanId;
}

export function scanScratchRoot(config: ScratchConfig, scanId: string): string {
  return join(resolve(config.WORKER_SCRATCH_DIR), assertSafeScanId(scanId));
}

export function scanScratchPaths(config: ScratchConfig, scanId: string): ScanScratch {
  const root = scanScratchRoot(config, scanId);
  return { root, sourceDir: join(root, 'src'), outputDir: join(root, 'out') };
}

/**
 * Creates a fresh, empty scratch tree for a scan.
 *
 * Any leftover tree is removed first: this runs on every attempt, so a retry or a
 * resumed job never inherits a half-fetched checkout from a previous run.
 */
export async function prepareScanScratch(
  config: ScratchConfig,
  scanId: string,
): Promise<ScanScratch> {
  const paths = scanScratchPaths(config, scanId);

  await cleanupScanScratch(config, scanId);
  await mkdir(paths.sourceDir, { recursive: true });
  await mkdir(paths.outputDir, { recursive: true });

  return paths;
}

/**
 * Removes a scan's scratch tree.
 *
 * Returns `false` instead of throwing: a cleanup failure must never fail an
 * otherwise-complete scan. Windows holds file handles inside `.git`, so a bare
 * `rm` can raise EPERM — hence the retries.
 */
export async function cleanupScanScratch(
  config: ScratchConfig,
  scanId: string,
): Promise<boolean> {
  const root = scanScratchRoot(config, scanId);

  try {
    await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    return true;
  } catch (error) {
    logger.warn({ scanId, root, err: error }, 'failed to remove scan scratch directory');
    return false;
  }
}

/**
 * Removes scratch trees left behind by a worker that was killed mid-scan.
 *
 * `cleanupScanScratch` covers the normal path; this covers the process that dies
 * before it can run. Only directories whose mtime is older than `olderThanMs` are
 * touched, so an in-flight scan is never deleted out from under its own job.
 */
export async function sweepStaleScratch(
  config: ScratchConfig,
  olderThanMs: number,
): Promise<number> {
  const base = resolve(config.WORKER_SCRATCH_DIR);

  let entries: string[];
  try {
    entries = await readdir(base);
  } catch {
    // The scratch root does not exist yet: nothing to sweep.
    return 0;
  }

  const cutoff = Date.now() - olderThanMs;
  let removed = 0;

  for (const entry of entries) {
    if (!SAFE_SCAN_ID.test(entry)) continue;

    const full = join(base, entry);

    try {
      const info = await stat(full);
      if (!info.isDirectory()) continue;
      if (info.mtimeMs > cutoff) continue;

      await rm(full, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      removed += 1;
      logger.warn(
        { scanId: entry, ageMs: Date.now() - info.mtimeMs },
        'swept stale scan scratch directory',
      );
    } catch {
      // Best effort: one undeletable directory must not stop the sweep.
    }
  }

  return removed;
}
