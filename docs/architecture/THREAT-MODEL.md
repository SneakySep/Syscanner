# Syscanner — Threat Model

> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md). Scope: the **scanner plane**,
> where hostile customer repositories are processed.

## 1. Assets under protection

| Asset | Why it matters | Impact if lost |
|---|---|---|
| Customer source code | The customer's crown jewels; we clone it daily | Catastrophic breach, contract loss |
| Detected secrets | We *find* credentials — we must never leak them | Third-party account takeover |
| SCM access tokens | Grant read access to all customer repos | Full supply-chain compromise |
| Findings database | Reveals unpatched weaknesses across tenants | Targeted exploitation of customers |
| Control plane (API/DB/Redis) | Single point of trust for all tenants | Multi-tenant breach |
| Compute budget | Sandboxes are attacker-controllable | Denial of wallet |

## 2. Trust boundaries

```
   Internet ──▶ Edge ──▶ Control plane ──▶ Worker host ──▶ [ TRUST BOUNDARY ] ──▶ Sandbox
                                                            untrusted code lives here
```

The sandbox is the only place untrusted code runs. Everything to its right is trusted
and must never be reachable *from* it.

## 3. Threat catalogue and required controls

| # | Attack | Real-world vector | Required control |
|---|---|---|---|
| T1 | Container/sandbox escape | Kernel exploit, exposed Docker socket, `--privileged` | gVisor/Kata microVM; no socket mounts; no privileged; seccomp + AppArmor |
| T2 | Resource exhaustion | Fork bomb, 8 GB alloc, decompression bomb, infinite loop | cgroup v2 CPU/mem/**pids** caps + hard wall-clock kill of the whole cgroup |
| T3 | Egress / exfiltration | `curl` metadata service, POST secrets to attacker host, DNS tunneling | `--network none` by default; allowlist proxy; deny RFC1918 + `169.254.169.254`; DNS pinning |
| T4 | Lateral movement | Reach PostgreSQL/Redis/API on a flat network | NetworkPolicy default-deny; sandbox has no route to control plane; no DB creds in sandbox env |
| T5 | Build-time code execution | `postinstall`, `prepare`, `setup.py`, `Makefile` | **Never build/install**; parse lockfiles offline; `ignore-scripts` if unavoidable |
| T6 | Git config abuse | Malicious hooks, submodules, `url.*.insteadOf`, smudge filters | `core.hooksPath=/dev/null`; `--no-recurse-submodules`; `protocol.file.allow=never`; `GIT_LFS_SKIP_SMUDGE=1` |
| T7 | Archive attacks | Path traversal, symlink escape, zip bomb | Traversal rejection, no out-of-root symlinks, entry/size/ratio caps |
| T8 | Parser exploitation | XXE in SARIF XML, `billion laughs`, malformed JSON RCE | Parse in trusted orchestrator, XML external entities disabled, schema validation, size caps |
| T9 | Output injection | Stored XSS via code snippet; bidi-spoofed finding text; queue/DB injection via SARIF fields | Escape all strings; store `snippetHash` not snippets; strip bidi overrides; validate against zod before DB |
| T10 | Denial of wallet | 10k findings/scan, huge repo, unbounded cache growth | Per-tenant quotas + concurrency limits; max repo size/file count/findings |
| T11 | Scanner config abuse | Repo ships a rule file that pulls remote rules or uploads telemetry | Trusted bundled rulesets only; `--metrics=off`; reject repo-supplied remote configs |
| T12 | Supply-chain via our images | Compromised `:latest` scanner image | Digest-pinned images verified with cosign/Sigstore; own SBOM per image |

## 4. Isolation requirements (normative)

A sandbox **MUST** be destroyed after a single job. It **MUST** run with:

- `user = 65534`, `readOnlyRootFilesystem = true`
- `capabilities: drop ALL` (add back nothing)
- `allowPrivilegeEscalation: false`, `no-new-privileges`
- seccomp profile denying `ptrace`, `mount`, `unshare`, `bpf`, `keyctl`
- `tmpfs` scratch, size-capped, `noexec,nosuid,nodev` where possible
- `memory` + `memorySwap` caps, `pids` limit, CPU quota
- `network: none` unless an explicit allowlist proxy is required
- wall-clock deadline enforced by the **orchestrator**, terminating the whole cgroup
- **no** credentials, no DB URL, no Redis URL, no SCM token in its environment

## 5. Verification

`packages/testing` ships a hostile-repo corpus executed in CI. The build **FAILS** if any
fixture achieves network egress, exceeds its memory cap, or writes outside its working
directory. See `packages/testing/src/fixtures/malicious/`.

## 6. Residual risk (accepted, monitored)

| Risk | Mitigation in place | Monitor |
|---|---|---|
| gVisor bug enabling escape | Vendor patching cadence; dedicated node pool | Host kernel + `runsc` alerting; SIEM on anomalous syscalls |
| Malicious rule file causing false negatives | Trusted ruleset pinning | Rule-set version drift alerting |
| Customer-visible secret stored in artifact | Short TTL (72 h default) + KMS encryption | Access audit logs on the artifacts bucket |
| Container runtime CVE | Minimal distroless images, rebuild pipeline | Image scanning on every build |
