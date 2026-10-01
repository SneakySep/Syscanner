import type { ViewerFinding } from '../../components/code-viewer/decorations';

/**
 * Fixture for the code-viewer demo route.
 *
 * This is **not** a real scan result. The architecture deliberately never persists
 * file contents — `Finding` stores a `snippetHash`, not the snippet — and there is no
 * endpoint that returns repository source yet, so there is nothing genuine to display.
 * A fixture is used so the viewer can be seen and exercised without pretending it is
 * wired to real data.
 *
 * The source is held as an explicit array of lines rather than one big template
 * literal, so the line numbers the findings reference are unambiguous and can be
 * asserted (see the fixture test).
 */
const LINES: readonly string[] = [
  '// Legacy reporting endpoints. Scheduled for replacement in Q3.', // 1
  "import { Router } from 'express';", // 2
  "import { createHash } from 'node:crypto';", // 3
  "import { db } from '../db/legacy/connection';", // 4
  "import { logger } from '../logger';", // 5
  '', // 6
  '// TODO: move to the secret manager before the next release.', // 7
  'const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";', // 8
  'const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";', // 9
  '', // 10
  'export const reportRouter = Router();', // 11
  '', // 12
  "reportRouter.get('/reports/:id', async (req, res) => {", // 13
  '  const reportId = req.params.id;', // 14
  '  const query = "SELECT * FROM reports WHERE id = " + reportId;', // 15
  '  const rows = await db.query(query);', // 16
  '  return res.json(rows);', // 17
  '});', // 18
  '', // 19
  "reportRouter.post('/reports/export', async (req, res) => {", // 20
  '  const { filename, contents } = req.body;', // 21
  "  const cacheKey = createHash('md5').update(contents).digest('hex');", // 22
  "  await db.query('INSERT INTO exports (key, name) VALUES ($1, $2)', [cacheKey, filename]);", // 23
  '  return res.status(201).json({ key: cacheKey });', // 24
  '});', // 25
  '', // 26
  "reportRouter.post('/reports/preview', async (req, res) => {", // 27
  '  const expression = req.body.expression;', // 28
  '  const evaluated = eval(expression);', // 29
  '  return res.json({ result: evaluated });', // 30
  '});', // 31
  '', // 32
  "reportRouter.get('/reports/:id/pdf', async (req, res) => {", // 33
  '  const id = req.params.id;', // 34
  '  logger.info("rendering report", { id });', // 35
  '  const output = await renderPdf(id);', // 36
  '  return res.send(output);', // 37
  '});', // 38
];

export const FIXTURE_LINE_COUNT = LINES.length;

export const FIXTURE_CODE = LINES.join('\n');

export const FIXTURE_PATH = 'src/api/routes/legacyReports.ts';

export const FIXTURE_LANGUAGE = 'typescript';

/**
 * Findings for the fixture, spanning CRITICAL, HIGH, MEDIUM and LOW so the sidebar
 * and the decoration palette are both fully exercised.
 *
 * `suggestedFix` is hand-written here because the schema has no remediation column
 * and the SARIF parser does not yet extract `result.fixes` — that gap is why these
 * are authored rather than produced.
 */
export const FIXTURE_FINDINGS: readonly ViewerFinding[] = [
  {
    id: 'fixture-sqli',
    severity: 'CRITICAL',
    line: 15,
    endLine: 16,
    ruleId: 'javascript.lang.security.audit.sqli.node-mysql-sqli',
    title: 'User input concatenated directly into a SQL query',
    suggestedFix:
      'Use a parameterised query: db.query("SELECT * FROM reports WHERE id = $1", [reportId]).',
  },
  {
    id: 'fixture-aws-key',
    severity: 'CRITICAL',
    line: 8,
    ruleId: 'aws-access-token',
    title: 'Hardcoded AWS access key id',
    suggestedFix: 'Revoke this key, then load the credential from the secret manager at runtime.',
  },
  {
    id: 'fixture-eval',
    severity: 'HIGH',
    line: 29,
    ruleId: 'javascript.lang.security.audit.eval-detected',
    title: 'Dynamic code execution via eval on request input',
    suggestedFix:
      'Remove the eval and parse the expression against an allow-list of supported operations.',
  },
  {
    id: 'fixture-aws-secret',
    severity: 'MEDIUM',
    line: 9,
    ruleId: 'aws-secret-access-key',
    title: 'Hardcoded AWS secret access key',
    suggestedFix: 'Rotate the credential and read it from the environment or a secret manager.',
  },
  {
    id: 'fixture-md5',
    severity: 'MEDIUM',
    line: 22,
    ruleId: 'javascript.lang.security.audit.insecure-hash-algorithm',
    title: 'MD5 used for a cache key',
    suggestedFix: "Use createHash('sha256') — MD5 is not collision resistant.",
  },
  {
    id: 'fixture-no-rate-limit',
    severity: 'LOW',
    line: 33,
    ruleId: 'javascript.express.security.audit.express-missing-rate-limit',
    title: 'Route renders a PDF without a rate limit or authorisation check',
    suggestedFix: 'Add the auth middleware and a per-tenant rate limiter to this route.',
  },
  {
    id: 'fixture-out-of-range',
    severity: 'INFO',
    line: 9_999,
    ruleId: 'fixture.out-of-range',
    title: 'Finding recorded against a line past the end of this revision',
    suggestedFix:
      'Demonstrates clamping: findings can reference a different revision, and the viewer anchors rather than breaking.',
  },
];