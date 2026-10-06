// tools/mirror.mjs end to end, against a fake edge and a real temporary git repository.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { renderLatest, renderSegment } from '../tools/lib/canonical.mjs';
import { gitClock, runMirror } from '../tools/mirror.mjs';
import { devFixtures, edgeFetch, issueEntries, ORIGIN, renderLog, silent, tempRepo } from './helpers.mjs';

const at = (iso) => () => new Date(iso);
const mirror = (dir, files, opts = {}) =>
  runMirror({ repo: dir, origin: ORIGIN, env: 'dev', fetchImpl: edgeFetch(files, opts), now: at(opts.now ?? '2026-10-06T09:16:06Z'), commit: true, log: silent, ...opts.run });

test('first run on the live dev files: one commit with the log, the key set and the checkpoint', async () => {
  const { dir, git } = tempRepo();
  const out = await mirror(dir, devFixtures());
  assert.equal(out.outcome, 'changed');
  assert.equal(out.committed, true);
  const files = git('show', '--name-only', '--format=', 'HEAD').split('\n').sort();
  assert.deepEqual(files, ['checkpoints/20261001T002021Z_0.jws', 'ct/0.json', 'ct/checkpoint-latest.json', 'ct/latest.json', 'jwks.json']);
  for (const [path, bytes] of Object.entries(devFixtures())) assert.ok(readFileSync(join(dir, path)).equals(bytes), `${path} is byte for byte as served`);
  const message = git('log', '-1', '--format=%B');
  assert.match(message, /^mirror: head seq 0 in segment 0, checkpoint 2026-10-01T00:20:21Z/);
  assert.match(message, /latest\.json SHA-256: [0-9a-f]{64}/);
  assert.match(message, /Fetched at: 2026-10-06T09:16:06Z/);
});

test('second run with nothing new: no commit', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const head = git('rev-parse', 'HEAD');
  const out = await mirror(dir, devFixtures());
  assert.equal(out.outcome, 'unchanged');
  assert.equal(out.committed, false);
  assert.equal(git('rev-parse', 'HEAD'), head);
});

test('a run that sees only a new generatedAt commits nothing', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const head = git('rev-parse', 'HEAD');
  const files = devFixtures();
  files['ct/latest.json'] = Buffer.from(files['ct/latest.json'].toString().replace('2026-10-05T23:20:27Z', '2026-10-06T10:20:00Z'));
  const out = await mirror(dir, files);
  assert.equal(out.committed, false);
  assert.equal(git('rev-parse', 'HEAD'), head);
});

test('prod before the edge serves /ct/*: 404 is "not published yet": no commit, green, a notice', async () => {
  const { dir, git } = tempRepo();
  const head = git('rev-parse', 'HEAD');
  const lines = [];
  const out = await runMirror({ repo: dir, origin: 'https://api.purposesource.org', env: 'prod', fetchImpl: edgeFetch({}, { origin: 'https://api.purposesource.org' }), commit: true, log: (l) => lines.push(l) });
  assert.equal(out.outcome, 'not-published');
  assert.equal(out.exitCode, 0);
  assert.equal(git('rev-parse', 'HEAD'), head);
  assert.ok(lines.some((l) => l.startsWith('::notice::') && l.includes('not published')));
});

test('an unset PSN_ORIGIN switches the mirror off without reading anything', async () => {
  const { dir } = tempRepo();
  const fetchImpl = edgeFetch(devFixtures());
  const out = await runMirror({ repo: dir, origin: '', env: 'prod', fetchImpl, log: silent });
  assert.equal(out.outcome, 'off');
  assert.equal(fetchImpl.asked.length, 0);
});

test('segments come from latest.json\'s segment field, never by probing the next one (correction 3)', async () => {
  const { dir } = tempRepo();
  const fetchImpl = edgeFetch(devFixtures());
  await runMirror({ repo: dir, origin: ORIGIN, env: 'dev', fetchImpl, log: silent });
  assert.deepEqual(fetchImpl.asked.map((u) => u.slice(ORIGIN.length)), ['/ct/latest.json', '/ct/0.json', '/ct/checkpoint-latest.json', '/jwks.json']);
});

test('an incident: nothing in ct/ moves, the evidence is committed under incidents/{stamp}/, and the run reports it', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const files = devFixtures();
  const rewritten = files['ct/latest.json'].toString().replace('b54fda77', 'c54fda77');
  files['ct/latest.json'] = Buffer.from(rewritten);
  files['ct/0.json'] = Buffer.from(files['ct/0.json'].toString().replace('b54fda77', 'c54fda77'));
  const out = await mirror(dir, files, { now: '2026-10-06T10:37:00Z' });
  assert.equal(out.outcome, 'incident');
  assert.equal(out.incident, true);
  assert.equal(out.committed, true);
  const changed = git('show', '--name-only', '--format=', 'HEAD').split('\n');
  assert.ok(changed.every((p) => p.startsWith('incidents/20261006T103700Z/')), changed.join(','));
  assert.ok(existsSync(join(dir, 'incidents/20261006T103700Z/ct/latest.json')));
  const record = JSON.parse(readFileSync(join(dir, 'incidents/20261006T103700Z/files.json'), 'utf8'));
  assert.ok(record.reasons.some((r) => r.includes('disagree at seq 0')));
  assert.equal(readFileSync(join(dir, 'incidents/20261006T103700Z/reason.txt'), 'utf8').split('\n').length, 2);
  assert.ok(readFileSync(join(dir, 'ct/latest.json')).equals(devFixtures()['ct/latest.json']), 'ct/ is left alone');
});

test('an incident whose served file fails its schema or the no-names rule keeps only its SHA-256 and the reason (correction 8)', async () => {
  const { dir } = tempRepo();
  const files = devFixtures();
  const leaked = JSON.parse(files['ct/latest.json'].toString());
  leaked.entries[0].subject = 'jane.doe@example.org';
  files['ct/latest.json'] = Buffer.from(JSON.stringify(leaked, null, 2) + '\n');
  const out = await mirror(dir, files, { now: '2026-10-06T10:37:00Z' });
  assert.equal(out.outcome, 'incident');
  const folder = join(dir, 'incidents/20261006T103700Z');
  assert.equal(existsSync(join(folder, 'ct/latest.json')), false, 'the leaking bytes are not committed');
  const record = JSON.parse(readFileSync(join(folder, 'files.json'), 'utf8'));
  const entry = record.files.find((f) => f.path === 'ct/latest.json');
  assert.equal(entry.kept, false);
  assert.match(entry.sha256, /^[0-9a-f]{64}$/);
  assert.ok(entry.withheldBecause);
  const all = readdirSync(folder, { recursive: true }).map(String).filter((f) => statSync(join(folder, f)).isFile()).map((f) => readFileSync(join(folder, f), 'utf8')).join('');
  assert.ok(!all.includes('jane'), 'the name never reaches the repository');
  assert.ok(!out.incidentRecord.reasons.join(' ').includes('jane'));
});

test('the same incident seen again is not recorded twice', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const files = devFixtures();
  files['ct/0.json'] = Buffer.from(files['ct/0.json'].toString().replace('b54fda77', 'c54fda77'));
  files['ct/latest.json'] = Buffer.from(files['ct/latest.json'].toString().replace('b54fda77', 'c54fda77'));
  await mirror(dir, files, { now: '2026-10-06T10:37:00Z' });
  const head = git('rev-parse', 'HEAD');
  const again = await mirror(dir, files, { now: '2026-10-06T11:37:00Z' });
  assert.equal(again.incident, true);
  assert.equal(again.committed, false);
  assert.equal(git('rev-parse', 'HEAD'), head);
  assert.equal(again.incidentRecord.repeated, true);
});

test('the same incident re-rendered with a new generatedAt is still one incident', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const files = devFixtures();
  files['ct/0.json'] = Buffer.from(files['ct/0.json'].toString().replace('b54fda77', 'c54fda77'));
  files['ct/latest.json'] = Buffer.from(files['ct/latest.json'].toString().replace('b54fda77', 'c54fda77'));
  await mirror(dir, files, { now: '2026-10-06T10:37:00Z' });
  const head = git('rev-parse', 'HEAD');
  files['ct/latest.json'] = Buffer.from(files['ct/latest.json'].toString().replace('2026-10-05T23:20:27Z', '2026-10-06T11:20:00Z'));
  const again = await mirror(dir, files, { now: '2026-10-06T11:37:00Z' });
  assert.equal(again.committed, false);
  assert.equal(git('rev-parse', 'HEAD'), head);
});

test('a 503 from the edge: green, a warning, no commit', async () => {
  const { dir, git } = tempRepo();
  const head = git('rev-parse', 'HEAD');
  const out = await mirror(dir, devFixtures(), { statuses: { 'jwks.json': 503 } });
  assert.equal(out.outcome, 'unreadable');
  assert.equal(out.exitCode, 0);
  assert.equal(git('rev-parse', 'HEAD'), head);
});

test('dry run: says what it would commit and writes nothing', async () => {
  const { dir, git } = tempRepo();
  const lines = [];
  const out = await runMirror({ repo: dir, origin: ORIGIN, env: 'dev', fetchImpl: edgeFetch(devFixtures()), dryRun: true, commit: true, log: (l) => lines.push(l) });
  assert.equal(out.outcome, 'changed');
  assert.equal(existsSync(join(dir, 'ct')), false);
  assert.equal(git('status', '--porcelain'), '');
  assert.ok(lines.some((l) => l.includes('would commit')));
});

test('a wrong PSN_ENV on an empty mirror is "misconfigured": red, no commit, no incident, no issue', async () => {
  const { dir, git } = tempRepo();
  const head = git('rev-parse', 'HEAD');
  const lines = [];
  const out = await runMirror({ repo: dir, origin: ORIGIN, env: 'prod', fetchImpl: edgeFetch(devFixtures()), commit: true, log: (l) => lines.push(l) });
  assert.equal(out.outcome, 'misconfigured');
  assert.equal(out.exitCode, 1);
  assert.equal(out.committed, false);
  assert.equal(out.incident, false, 'no issue is opened for a setting error');
  assert.equal(git('rev-parse', 'HEAD'), head);
  assert.equal(existsSync(join(dir, 'incidents')), false);
  assert.ok(lines.some((l) => l.startsWith('::error::') && l.includes('psn-dev-2026-2') && l.includes('PSN_ENV')), lines.join('\n'));
});

test('a served file with CRLF line ends is an incident whose evidence is kept exactly as served, CRs included', async () => {
  const { dir } = tempRepo();
  await mirror(dir, devFixtures());
  const files = devFixtures();
  const crlf = Buffer.from(files['ct/latest.json'].toString().replaceAll('\n', '\r\n'));
  files['ct/latest.json'] = crlf;
  const out = await mirror(dir, files, { now: '2026-10-06T10:37:00Z' });
  assert.equal(out.outcome, 'incident');
  assert.ok(readFileSync(join(dir, 'incidents/20261006T103700Z/ct/latest.json')).equals(crlf), 'the evidence is byte for byte as served');
});

test('cache windows on the git clock: a shorter latest.json just after the commit is a stale read; 3 hours later it is an incident', async () => {
  const { dir, git } = tempRepo();
  await mirror(dir, devFixtures());
  const head = git('rev-parse', 'HEAD');
  const committed = Number(git('log', '-1', '--format=%ct')) * 1000;
  const files = devFixtures();
  const latest = JSON.parse(files['ct/latest.json'].toString());
  files['ct/latest.json'] = renderLatest({ ...latest, entries: [], generatedAt: '2026-10-05T00:00:00Z' });
  files['ct/0.json'] = renderSegment({ ...latest, entries: [] });
  const soon = await mirror(dir, files, { now: new Date(committed + 60_000).toISOString() });
  assert.equal(soon.outcome, 'unchanged');
  assert.deepEqual(soon.result.stale.sort(), ['ct/0.json', 'ct/latest.json']);
  assert.equal(git('rev-parse', 'HEAD'), head);
  const later = await mirror(dir, files, { now: new Date(committed + 3 * 3_600_000).toISOString() });
  assert.equal(later.outcome, 'incident');
  assert.ok(later.result.incidents.some((p) => p.startsWith('ct/latest.json as served ends at head seq none')), JSON.stringify(later.result.incidents));
  assert.ok(!later.result.incidents.some((p) => p.startsWith('ct/0.json')), 'ct/0.json is still inside its 26-hour window');
});

test('gitClock reads the commit dates: when a path was last committed, and since when latest.json has named a segment', () => {
  const { dir } = tempRepo();
  const commitAt = (date, message) => {
    execFileSync('git', ['add', '-A'], { cwd: dir });
    execFileSync('git', ['commit', '-q', '-m', message], { cwd: dir, env: { ...process.env, GIT_COMMITTER_DATE: date, GIT_AUTHOR_DATE: date } });
  };
  mkdirSync(join(dir, 'ct'));
  writeFileSync(join(dir, 'ct/latest.json'), renderLog(issueEntries(9999))['ct/latest.json']);
  commitAt('2026-10-01T00:00:00Z', 'segment 0');
  writeFileSync(join(dir, 'ct/latest.json'), renderLog(issueEntries(10001))['ct/latest.json']);
  commitAt('2026-10-02T00:00:00Z', 'segment 1');
  writeFileSync(join(dir, 'ct/latest.json'), renderLog(issueEntries(10002))['ct/latest.json']);
  commitAt('2026-10-03T00:00:00Z', 'segment 1 grew');
  const clock = gitClock(dir, Date.parse('2026-10-04T00:00:00Z'));
  assert.equal(clock.committedAt('ct/latest.json'), Date.parse('2026-10-03T00:00:00Z'));
  assert.equal(clock.committedAt('ct/0.json'), null);
  assert.equal(clock.heldSince(1), Date.parse('2026-10-02T00:00:00Z'));
  assert.equal(clock.heldSince(0), Date.parse('2026-10-01T00:00:00Z'));
  assert.equal(clock.heldSince(2), null);
});

test('a misconfigured environment name is red', async () => {
  const { dir } = tempRepo();
  const out = await runMirror({ repo: dir, origin: ORIGIN, env: 'staging', fetchImpl: edgeFetch({}), log: silent });
  assert.equal(out.exitCode, 1);
});
