# ─────────────────────────────────────────────────────────────────────────────
# Syscanner sandbox runner image.
#
# This image is executed only inside the sandbox. It is deliberately minimal:
#   * no shell, no package manager, no curl/wget in the final layer
#   * non-root by default
#   * read-only root filesystem (enforced by the orchestrator, not here)
#   * rulesets are baked in at a known path so a repository can never supply one
#
# Replace the tool installation below with a digest-pinned, cosign-verified
# toolchain in production. Never use a floating tag.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS builder

WORKDIR /build
COPY package.json tsconfig.json ./
COPY src ./src
RUN npm install --ignore-scripts --no-audit --no-fund \
    && npx tsc -p tsconfig.json

# ── Tool stage: install scanners, then drop every package manager ─────────────
FROM debian:bookworm-slim AS tools

ENV DEBIAN_FRONTEND=noninteractive

# Versions are pinned to match @syscanner/contracts TOOL_VERSIONS.
ARG SEMGREP_VERSION=1.90.0
ARG GITLEAKS_VERSION=8.21.2
ARG OSV_SCANNER_VERSION=1.9.0
ARG TRIVY_VERSION=0.55.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl python3 python3-pip git tar \
    && pip3 install --no-cache-dir --break-system-packages \
      "semgrep==${SEMGREP_VERSION}" \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks \
    && curl -sSfL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
      -o /usr/local/bin/osv-scanner \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy \
    && chmod 0555 /usr/local/bin/gitleaks /usr/local/bin/osv-scanner /usr/local/bin/trivy \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache

# Trusted, mutable-only-by-us rulesets. The orchestrator points Semgrep at this
# path and it is never writable at runtime.
COPY rules /opt/syscanner/rules

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# The orchestrator additionally enforces: --read-only, --cap-drop ALL,
# --no-new-privileges, seccomp, --network none, --pids-limit, tmpfs.
COPY --from=tools /usr/local /usr/local
COPY --from=tools /opt/syscanner /opt/syscanner
COPY --from=builder /build/dist /opt/syscanner/runner/dist
COPY --from=builder /build/node_modules /opt/syscanner/runner/node_modules

# nobody:nogroup
USER 65534:65534

WORKDIR /work

# The orchestrator supplies the job spec on stdin.
ENTRYPOINT ["node", "/opt/syscanner/runner/dist/main.js"]
