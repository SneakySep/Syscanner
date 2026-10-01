/**
 * Local development seed.
 *
 * Creates one tenant with an owner, a connected repository and a completed scan
 * containing representative findings across every severity, including CVE/CWE
 * data, file paths and line numbers so the dashboard has something real to render.
 *
 * Run with:  pnpm db:seed
 */
import {
  PrismaClient,
  Role,
  ScmProvider,
  ScanStatus,
  ScannerKind,
  Severity,
  FindingStatus,
  TaskStatus,
} from '@prisma/client';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const organization = await prisma.organization.upsert({
    where: { slug: 'acme' },
    update: {},
    create: {
      name: 'Acme Corp',
      slug: 'acme',
      plan: 'pro',
      maxConcurrentScans: 4,
      monthlyScanQuota: 500,
      retentionDays: 180,
    },
  });

  const user = await prisma.user.upsert({
    where: { email: 'security@acme.example' },
    update: {},
    create: {
      email: 'security@acme.example',
      name: 'Acme Security Lead',
      emailVerified: new Date(),
    },
  });

  await prisma.membership.upsert({
    where: { userId_organizationId: { userId: user.id, organizationId: organization.id } },
    update: { role: Role.OWNER },
    create: { userId: user.id, organizationId: organization.id, role: Role.OWNER },
  });

  const repository = await prisma.repository.upsert({
    where: {
      organizationId_fullName: { organizationId: organization.id, fullName: 'acme/backend' },
    },
    update: {},
    create: {
      organizationId: organization.id,
      provider: ScmProvider.GITHUB,
      providerRepoId: '81234567',
      fullName: 'acme/backend',
      cloneUrl: 'https://github.com/acme/backend.git',
      defaultBranch: 'main',
      isPrivate: true,
      language: 'TypeScript',
      sizeKb: 48213,
      credentialRef: 'vault://scm/acme/backend',
      scanConfig: {
        scanners: ['SAST', 'SECRETS', 'DEPENDENCY'],
        excludePaths: ['vendor/**', '**/*.min.js'],
        failOn: 'HIGH',
      },
    },
  });

  const commitSha = 'f3a91c7d2b8e45016cd9a0f17e2b3c4d5e6f7a8b';
  const toolVersions = { semgrep: '1.90.0', gitleaks: '8.21.2', 'osv-scanner': '1.9.0' };
  const inputFingerprint = 'a'.repeat(64);

  const scan = await prisma.scan.upsert({
    where: {
      repositoryId_commitSha_inputFingerprint: {
        repositoryId: repository.id,
        commitSha,
        inputFingerprint,
      },
    },
    update: {},
    create: {
      organizationId: organization.id,
      repositoryId: repository.id,
      triggeredById: user.id,
      status: ScanStatus.COMPLETED,
      branch: 'main',
      commitSha,
      inputFingerprint,
      policyVersion: 1,
      toolVersions,
      workerImage: `syscanner/sandbox-runner@sha256:${'0'.repeat(64)}`,
      totalFindings: 5,
      criticalCount: 1,
      highCount: 2,
      mediumCount: 1,
      lowCount: 1,
      filesScanned: 1840,
      linesScanned: 152330,
      sarifArtifactKey: 'scans/scan_demo/scan.sarif',
      durationMs: 41500,
      startedAt: new Date(Date.now() - 90000),
      finishedAt: new Date(Date.now() - 48500),
    },
  });

  const sastTask = await prisma.scanTask.upsert({
    where: { scanId_kind_tool: { scanId: scan.id, kind: ScannerKind.SAST, tool: 'semgrep' } },
    update: {},
    create: {
      scanId: scan.id,
      kind: ScannerKind.SAST,
      tool: 'semgrep',
      toolVersion: toolVersions.semgrep,
      status: TaskStatus.SUCCEEDED,
      exitCode: 0,
      durationMs: 21400,
    },
  });

  const findings = [
    {
      fingerprint: 'b'.repeat(64),
      taskId: sastTask.id,
      kind: ScannerKind.SAST,
      scanner: 'semgrep',
      ruleId: 'javascript.express.security.audit.express-check-csurf-middleware-usage',
      title: 'Missing CSRF middleware on a state-changing route',
      category: 'csrf',
      severity: Severity.HIGH,
      cvssScore: '7.5',
      cweIds: ['CWE-352'],
      owaspCategory: 'A01:2021-Broken Access Control',
      filePath: 'src/api/routes/account.ts',
      startLine: 42,
      endLine: 58,
      startColumn: 3,
      endColumn: 19,
      status: FindingStatus.OPEN,
    },
    {
      fingerprint: 'c'.repeat(64),
      taskId: sastTask.id,
      kind: ScannerKind.SAST,
      scanner: 'semgrep',
      ruleId: 'javascript.lang.security.audit.sqli.node-mysql-sqli',
      title: 'User input concatenated into a SQL query',
      category: 'sql-injection',
      severity: Severity.CRITICAL,
      cvssScore: '9.8',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cweIds: ['CWE-89'],
      owaspCategory: 'A03:2021-Injection',
      filePath: 'src/db/legacy/reportQueries.ts',
      startLine: 118,
      endLine: 124,
      startColumn: 5,
      endColumn: 44,
      status: FindingStatus.OPEN,
    },
    {
      fingerprint: 'd'.repeat(64),
      kind: ScannerKind.DEPENDENCY,
      scanner: 'osv-scanner',
      ruleId: 'GHSA-35jh-r3h4-6jhm',
      title: 'lodash prototype pollution in zipObjectDeep',
      category: 'vulnerable-dependency',
      severity: Severity.HIGH,
      cvssScore: '7.2',
      cveIds: ['CVE-2021-23337'],
      ghsaId: 'GHSA-35jh-r3h4-6jhm',
      cweIds: ['CWE-1321'],
      packageName: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      ecosystem: 'npm',
      dependencyPath: 'acme/backend > reporting-service > lodash',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
      status: FindingStatus.OPEN,
    },
    {
      fingerprint: 'e'.repeat(64),
      kind: ScannerKind.SECRETS,
      scanner: 'gitleaks',
      ruleId: 'aws-access-token',
      title: 'Hardcoded AWS access key detected',
      category: 'hardcoded-secret',
      severity: Severity.MEDIUM,
      cweIds: ['CWE-798'],
      filePath: 'infra/scripts/upload-artifacts.sh',
      startLine: 7,
      // Only a hash of the match is stored — the raw secret is never persisted.
      snippetHash: 'f'.repeat(64),
      status: FindingStatus.OPEN,
    },
    {
      fingerprint: '1'.repeat(64),
      kind: ScannerKind.LICENSE,
      scanner: 'trivy',
      ruleId: 'GPL-3.0-only',
      title: 'GPL-3.0 dependency in a distributed product',
      category: 'license-policy',
      severity: Severity.LOW,
      packageName: 'libfoo',
      packageVersion: '2.4.0',
      ecosystem: 'npm',
      status: FindingStatus.OPEN,
    },
  ] as const;

  for (const finding of findings) {
    await prisma.finding.upsert({
      where: { scanId_fingerprint: { scanId: scan.id, fingerprint: finding.fingerprint } },
      update: {},
      create: {
        ...finding,
        scanId: scan.id,
        repositoryId: repository.id,
        organizationId: organization.id,
      },
    });
  }

  await prisma.repository.update({
    where: { id: repository.id },
    data: { lastScanAt: scan.finishedAt ?? new Date() },
  });

  console.log(
    `Seeded tenant "${organization.slug}": ${findings.length} findings on scan ${scan.id}.`,
  );
}

main()
  .catch((error: unknown) => {
    console.error('Seed failed:', error);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
