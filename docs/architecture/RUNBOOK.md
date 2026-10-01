# Syscanner — Operations Runbook

> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md). Every procedure below assumes the
> operator has access to the control plane and the observability stack, but **not** the
> sandbox host filesystem.

## 1. Service map & health checks

| Service | Health probe | Owner |
|---|---|---|
| `apps/web` | `GET /api/health` | Platform |
| `apps/api` | `GET /healthz`, `GET /readyz` (DB + Redis) | Platform |
| `apps/worker` | BullMQ queue depth metric `syscanner_queue_depth` | Platform |
| PostgreSQL | `pg_isready` + replica lag | Data |
| Redis | `PING` + keyspace hit rate | Data |
| Sandboxes | `syscanner_sandbox_start_total` vs `_exit_total` | Security Eng |

## 2. Alert response

### 2.1 `SandboxEgressBlocked` — sandbox attempted to reach the network

**Severity: HIGH.** A `--network none` job should emit **zero** egress bytes.

1. Confirm the verdict in the egress proxy log and capture the destination IP.
2. Correlate `scanId` → `repositoryId` → customer.
3. Treat as a **hostile repository**. Do not re-run the scan on the same host.
4. Quarantine: mark the repo scan as `FAILED`, block further scans for that repo.
5. Notify the customer per the security-notification SLA.
6. File an incident; if the destination was an internal address, escalate to a
   **presumed-breach** review (see §3.1).

### 2.2 `SandboxOOMKilled` / `SandboxPidsLimitHit`

**Severity: MEDIUM.** Usually a fork bomb, a crypto-miner, or a legitimately huge repo.

1. Check `ScanTask.timedOut` and peak RSS in metrics.
2. If memory spike is proportionate to repo size → raise the cap for that tenant only.
3. If `pids` limit hit with flat memory → **hostile**, follow §2.1 steps 3–6.

### 2.3 `QueueDepthHigh` — `scan:orchestrate` depth > threshold for 10 min

1. Check worker replica count and last deploy.
2. Check for a stuck job: `ScanTask.status = RUNNING` with `startedAt` older than the
   sandbox timeout → the reaper will force-timeout it; verify the reaper is running.
3. Scale workers horizontally. **Do not** increase `WORKER_MAX_JOBS_PER_SANDBOX`; that
   violates the one-job-per-container invariant.

### 2.4 `FindingsIngestSpike` — abnormal findings insert volume

Possible causes: a huge new repo, a ruleset regression, or a scanner emitting noise after
an upgrade. Verify `policyVersion` + `toolVersions` on the affected scans, and roll back
the scanner image digest if correlated.

## 3. Incident playbooks

### 3.1 Suspected sandbox escape (presumed breach)

1. **Contain:** cordon the worker node pool, stop the orchestrator, drain BullMQ.
2. **Preserve:** snapshot the node's disk **before** rebooting; do not clean up.
3. **Scope:** enumerate all jobs that ran on that node in the last 30 days.
4. **Rotate everything** the node could reach: DB credentials, Redis AUTH, S3 keys, KMS
   grants, SCM tokens held in Vault, webhook HMAC secrets.
5. **Assess blast radius** against `AuditLog` and DB access logs.
6. **Disclose** per the customer contract; engage legal.

### 3.2 Detected secret exposed in an artifact

1. Delete the artifact object immediately (it may be customer-named).
2. Confirm the UI only ever rendered a masked match; check CDN/edge logs for the raw value.
3. Prompt the customer to rotate the credential (include the rule ID and file path).
4. Add the pattern to the shared redaction list in `packages/core/src/redaction.ts`.

### 3.3 PostgreSQL unavailable

1. `apps/api` returns `503` on `/readyz`; the ALB removes it from rotation. Expected.
2. Workers **must pause**, not fail: pause the queue so no scan is marked `FAILED`
   because of infrastructure. Use the reaper to requeue in-flight jobs.
3. Restore from PITR, then resume the queue.

### 3.4 Redis unavailable

Scans stop being scheduled but already-running sandboxes finish and their results buffer
in the orchestrator's local spool. Restore Redis, resume consumers, verify no duplicate
`Finding` rows (the `@@unique([scanId, fingerprint])` constraint makes this safe).

## 4. Routine operations

| Task | Command |
|---|---|
| Apply pending migrations | `pnpm db:migrate` |
| Validate schema without a DB | `pnpm db:validate` |
| Regenerate Prisma client | `pnpm db:generate` |
| Seed a local tenant | `pnpm db:seed` |
| Bring up local infra | `pnpm infra:up` |
| Tail worker logs | `docker compose -f infra/docker/docker-compose.yml logs -f worker` |
| Rotate KMS data key | Bump `KMS_KEY_ID`, run the re-encryption job, revoke the old key |

## 5. Escalation

| Condition | Escalate to | SLA |
|---|---|---|
| Confirmed sandbox escape | Security Eng + CTO | Immediate page |
| Egress-blocked event on a private IP | Security Eng | 15 min |
| Customer data in an artifact | Security Eng + Legal | 1 h |
| Extended ingest outage | Platform on-call | 30 min |
