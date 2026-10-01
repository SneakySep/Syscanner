/**
 * @syscanner/scanners — tool adapters and the hardened SARIF ingest path.
 *
 * SECURITY: this package is sandbox-adjacent. It must never be imported by
 * `apps/api` or `apps/web`; only `apps/worker` and `apps/sandbox-runner` may use
 * it. See §2.1 of docs/architecture/ARCHITECTURE.md.
 */
export * from './types';
export * from './sarif';
export * from './tools';
