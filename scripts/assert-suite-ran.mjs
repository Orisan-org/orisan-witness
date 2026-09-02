/**
 * Fail unless every local test file actually EXECUTED and none of its tests
 * were skipped, on this run.
 *
 * A green `npm test` does not establish that: `describe.skip` is green, a
 * renamed file that vitest's include glob silently stops matching is green,
 * and a deleted file is greenest of all. This script reads vitest's own
 * account of what happened rather than trusting its exit code, in the same
 * spirit as orisan-recorder's scripts/assert-witness-ran.mjs and
 * assert-attacks-ran.mjs.
 *
 * The expected file list below is deliberately not a count: a count like
 * "7 test files" only proves today's file set was unchanged, not that the
 * enumeration itself happened. Each name is checked individually, so a
 * rename or deletion is caught by name, and a *.test.ts file that exists on
 * disk but isn't named here is caught too — a gate that quietly narrowed to
 * fewer files than the repo actually has is exactly the failure mode this
 * exists to catch.
 *
 * test/tigris.live.test.ts is deliberately excluded: it dials a real
 * S3-compatible bucket and has its own gate on a schedule, see
 * .github/workflows/tigris-live.yml and scripts/assert-live-ran.mjs. Putting
 * a network call in this PR/push gate would make it flaky for reasons that
 * have nothing to do with the code under review.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const testDir = join(repo, 'test');

/** The files this gate is responsible for running. Not a count — a list. */
const EXPECTED = [
  'backup.test.ts',
  'db.test.ts',
  'restore.test.ts',
  's3.test.ts',
  'server.test.ts',
  'service.test.ts',
];

/** Exempted here, gated separately. See the file header. */
const LIVE_EXEMPT = ['tigris.live.test.ts'];

function fail(lines) {
  process.stderr.write(`\n${lines.join('\n')}\n\n`);
  process.exit(1);
}

if (EXPECTED.length === 0) fail(['EXPECTED is empty — this gate would assert nothing.']);

// 1. The directory is the ground truth for "renamed away or deleted": a name
// in EXPECTED that no longer exists on disk is exactly that failure. And a
// *.test.ts file on disk that is in neither EXPECTED nor LIVE_EXEMPT means
// someone added a suite that this gate never learned to run.
const onDisk = readdirSync(testDir).filter((f) => f.endsWith('.test.ts'));
const missing = EXPECTED.filter((f) => !onDisk.includes(f));
const unaccounted = onDisk.filter((f) => !EXPECTED.includes(f) && !LIVE_EXEMPT.includes(f));

if (missing.length > 0) {
  fail([
    `Expected test file(s) missing from test/: ${missing.join(', ')}`,
    'Renamed or deleted without updating scripts/assert-suite-ran.mjs.',
  ]);
}
if (unaccounted.length > 0) {
  fail([
    `test/ has file(s) this gate does not know about: ${unaccounted.join(', ')}`,
    'Add them to EXPECTED in scripts/assert-suite-ran.mjs (or to LIVE_EXEMPT if',
    'they are network-dependent), or the gate is narrower than the repo is.',
  ]);
}

// 2. Run exactly the expected files and read the reporter's own account of
// what happened, rather than trusting `npm test`'s exit code.
const targets = EXPECTED.map((f) => `test/${f}`);
let report;
try {
  const raw = execFileSync(
    'npx',
    ['vitest', 'run', '--reporter=json', ...targets],
    { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  report = JSON.parse(raw.slice(raw.indexOf('{')));
} catch (e) {
  fail(['The suite did not complete.', String(e.message ?? e).slice(0, 600)]);
}

const results = report.testResults ?? [];
const allTests = results.flatMap((f) => f.assertionResults ?? []);
if (allTests.length === 0) fail(['No tests were reported. The suite executed zero tests.']);

const problems = [];
for (const file of EXPECTED) {
  const fileResult = results.find((r) => r.name?.replace(/\\/g, '/').endsWith(`/test/${file}`));
  if (!fileResult) {
    problems.push(`${file}: no result reported by vitest — renamed, deleted, or failed to load`);
    continue;
  }
  const tests = fileResult.assertionResults ?? [];
  if (tests.length === 0) {
    problems.push(`${file}: reported but contributed zero tests`);
    continue;
  }
  const skipped = tests.filter((t) => t.status === 'skipped' || t.status === 'pending');
  if (skipped.length === tests.length) {
    problems.push(`${file}: all ${tests.length} test(s) skipped — the file did not actually execute`);
  } else if (skipped.length > 0) {
    problems.push(`${file}: ${skipped.length}/${tests.length} test(s) skipped`);
  }
  const failed = tests.filter((t) => t.status === 'failed');
  if (failed.length > 0) {
    problems.push(`${file}: ${failed.length}/${tests.length} test(s) failed`);
  }
}

if (problems.length > 0) {
  fail([
    'The local suite did not fully run.',
    'This gate exists so a skipped, renamed, or deleted test file fails the build',
    'instead of leaving a green tick that no longer means what it used to.',
    '',
    ...problems.map((p) => `  ${p}`),
  ]);
}

process.stdout.write(
  `\nAll ${EXPECTED.length} local test files ran and passed ` +
    `(${allTests.length} tests, 0 skipped, 0 failed).\n`,
);
