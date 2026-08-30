/**
 * Fail unless test/tigris.live.test.ts actually EXECUTED against a real
 * S3-compatible bucket, rather than self-skipping for lack of credentials.
 *
 * That file's own describe.skip is correct behaviour for the PR/push gate
 * (see scripts/assert-suite-ran.mjs, which excludes it on purpose) but it is
 * exactly wrong for the scheduled job that is supposed to be the thing
 * closing the loop on a real bucket: a schedule that has quietly been
 * skipping every run because a secret expired is not a check, it is the
 * appearance of one, and appearances don't need a cron trigger.
 */
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'test/tigris.live.test.ts';

function fail(lines) {
  process.stderr.write(`\n${lines.join('\n')}\n\n`);
  process.exit(1);
}

let report;
try {
  const raw = execFileSync(
    'npx',
    ['vitest', 'run', '--reporter=json', FILE],
    { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  report = JSON.parse(raw.slice(raw.indexOf('{')));
} catch (e) {
  fail([`${FILE} did not complete.`, String(e.message ?? e).slice(0, 600)]);
}

const results = (report.testResults ?? []).flatMap((f) => f.assertionResults ?? []);
if (results.length === 0) {
  fail([`No tests were reported for ${FILE}. It did not run at all.`]);
}

const skipped = results.filter((r) => r.status === 'skipped' || r.status === 'pending');
if (skipped.length > 0) {
  fail([
    `${skipped.length}/${results.length} live S3 test(s) were SKIPPED.`,
    'remoteFromEnv() found no client, which means AWS_ACCESS_KEY_ID,',
    'AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT_URL_S3 or BUCKET_NAME is missing or',
    'wrong in this scheduled run — check the repository secrets this workflow reads.',
  ]);
}

const failed = results.filter((r) => r.status !== 'passed');
if (failed.length > 0) {
  fail([
    `${failed.length}/${results.length} live S3 test(s) did not pass.`,
    ...failed.map((r) => `  ${r.fullName ?? r.title}: ${r.status}`),
  ]);
}

process.stdout.write(
  `\nAll ${results.length} live S3 test(s) ran against a real bucket and passed.\n`,
);
