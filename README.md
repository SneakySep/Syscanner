# Syscanner

**SAST · Secrets Detection · Dependency Vulnerability Scanning for Multi-Tenant SaaS.**

Syscanner clones a customer repository at an exact commit, runs Semgrep, Gitleaks,
osv-scanner and Trivy against it inside a throwaway sandbox, and normalizes the
results into one findings model with severities, CVE/CWE identifiers, file paths and
line numbers.

> **Read [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md) first.**
> It explains the trust model, the sandbox design, and the reasoning behind every
> decision below. [`THREAT-MODEL.md`](docs/architecture/THREAT-MODEL.md) and
> [`RUNBOOK.md`](docs/architecture/RUNBOOK.md) are its companions.

---

## Repository layout

```
apps/
  web/             Next.js 15 dashboard + BFF (SSE progress, findings table)
  api/             Fastify API gateway: authz, quotas, scan scheduling
  worker/          BullMQ consumers, git fetch, sandbox orchestration, SARIF ingest
                   src/dev/scanOneRepo.ts — UNSAFE local debugging script (dev only)
  sandbox-runner/  Entrypoint executed INSIDE the sandbox (no credentials, no network)
packages/
  db/              Prisma schema — the single source of truth for the data model
  core/            Pure domain logic: fingerprints, severity, redaction, policy
  queue/           BullMQ topology + zod-validated job contracts
  scanners/        Tool adapters and the hardened SARIF parser   (sandbox-only)
  contracts/       zod DTOs + pinned tool versions shared by web/api/worker
  crypto/          AES-256-GCM envelope encryption, HMAC verification, token hashing
  logger/          pino with mandatory redaction
  ui/              Shared React presentation primitives
  config/          Shared tsconfig / Prettier presets
  testing/         Hostile-repository corpus and containment assertions
infra/
  docker/          Postgres + Redis + MinIO for local development
  sandbox/         seccomp profile, default-deny egress policy, gVisor RuntimeClass
docs/architecture/ ARCHITECTURE.md · THREAT-MODEL.md · RUNBOOK.md
```

## Quick start

```bash
# 1. Toolchain
corepack enable                     # or: npm i -g pnpm@9.15.4
node --version                      # Node 20.11+ (22 recommended)

# 2. Dependencies
pnpm install

# 3. Local infrastructure (requires Docker)
pnpm infra:up                       # Postgres 5432, Redis 6379, MinIO 9000/9001
cp .env.example .env                # then fill in the values

# 4. Database
pnpm db:validate                    # offline schema check
pnpm --filter @syscanner/db run db:migrate
pnpm db:seed                        # one tenant, one repo, five representative findings

# 5. Run everything
pnpm dev                            # web :3000, api :4000, worker
```

## Quality gates

```bash
pnpm build       # turbo: build every package and app        (14 tasks)
pnpm typecheck   # turbo: tsc --noEmit across the workspace   (23 tasks)
pnpm test        # turbo: vitest                              (123 tests, 7 files)
pnpm db:validate # prisma validate — no database required
```

> **No linter is wired up yet.** `typecheck` and `test` are the enforced gates.
> Adding ESLint 9 + typescript-eslint as a flat config at the root is the intended
> next step; it was left out so the scaffold has no unnecessary install surface.

## Scanning one repository without Docker (development only)

When Docker is unavailable the sandbox cannot run. A deliberately **unsafe** fallback
exists for local debugging:

```bash
pnpm dev:scan-one -- https://github.com/octocat/Hello-World.git \
  --i-understand-this-is-not-sandboxed [--branch <name>] [--out findings.json]
```

It shallow-clones on the host, runs `semgrep scan --config=auto --json`, maps the
results into `Finding` rows, and tears the temp directory down in a `finally`.

It refuses to run when `NODE_ENV=production`, and refuses without the acknowledgement
flag, because it violates the threat model:

| | |
|---|---|
| **T1** | Nothing is sandboxed — Semgrep parses attacker-authored files in your process, on your host |
| **T3** | It has your network access and your environment |
| **T11** | `--config=auto` fetches rules from the Semgrep Registry, so results are neither offline nor reproducible |

The production equivalent — SHA-pinned fetch, sandboxed execution, image-bundled
ruleset — is `apps/worker/src/processors/scanRepository.ts`.

## Security model in one paragraph

The control plane is trusted; the scanner plane is not. A sandbox receives a
read-only source tree, an argv vector built by a trusted adapter, and an explicitly
constructed environment that contains no credentials — no database URL, no Redis
URL, no SCM token. It runs non-root, on a read-only root filesystem, with all
capabilities dropped, under seccomp, with CPU/memory/PID caps and a wall-clock
deadline enforced by the host. Egress is denied by default. The only thing it can
emit is a SARIF file into a single writable mount, and even that is size-capped,
schema-validated and sanitized before it reaches the database. Repository code is
never executed: we fetch an archive and parse lockfiles, so no `postinstall` hook,
`Makefile` or test suite ever runs.

## Known limitations (honest list)

| Area | Status |
|---|---|
| Sandbox execution | Not runnable here — **Docker is not installed on this machine**, so `infra:up` and real scans are unverified. The compose file, seccomp profile and provider code are authored and unit-verified only. |
| `pnpm dev:scan-one` | The unsafe dev fallback. Its guards are verified **by execution**: production refusal, acknowledgement gate, URL validation (a `file://` URL is refused), and temp-directory cleanup. The clone path was exercised end-to-end against `octocat/Hello-World` (0 temp dirs leaked). **Semgrep is not installed locally**, so the scan step itself is unverified. |
| Scanner binaries | Semgrep/Gitleaks/osv-scanner/Trivy are **not installed locally**. Adapters and the SARIF parser are fully tested; live tool invocation is untested. |
| Migrations | The schema validates and the client generates, but no `migration.sql` has been authored (that needs a live Postgres via `prisma migrate dev`). |
| Authentication | NextAuth is not wired up. The API trusts an `x-organization-id` header set by the API gateway, and the web app calls the API server-side only (`lib/api.ts` is the auth seam). |
| Branch-tip resolution | `POST /v1/repositories/:id/scans` requires an explicit `commitSha`; resolving a branch to a SHA needs the SCM client. |
| SSE progress | Implemented as a polling proxy in the web app; swap for the `syscanner:scan-progress:*` Redis pub/sub channel at scale (wire format unchanged). |
| Artifact storage | Findings are ingested, but SARIF is not yet uploaded to object storage (`sarifArtifactKey` is recorded as a local path). |
| Notification dispatch | The `notify:dispatch` queue and job contract exist; the Slack/email/GitHub-check senders are not implemented. |
