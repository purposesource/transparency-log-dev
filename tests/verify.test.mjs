// tools/verify.mjs: what anyone runs on a checkout, and its --history walk.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { published } from '../tools/lib/canonical.mjs';
import { runMirror } from '../tools/mirror.mjs';
import { verifyDirectory } from '../tools/verify.mjs';
import { devFixtures, edgeFetch, HERE, ORIGIN, silent, tempRepo } from './helpers.mjs';

async function mirroredRepo() {
  const repo = tempRepo();
  await runMirror({ repo: repo.dir, origin: ORIGIN, env: 'dev', fetchImpl: edgeFetch(devFixtures()), commit: true, log: silent });
  return repo;
}
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(list)}`);

/**
 * A commit on top of HEAD whose tree is `tree` (or HEAD's tree plus `name` under checkpoints/),
 * made through plumbing: no index and no checkout, so a name Windows refuses can be committed.
 */
function plumbingCommit(dir, { addName, bytes, tree } = {}) {
  const g = (args, input) => execFileSync('git', args, { cwd: dir, input, encoding: 'utf8' }).trim();
  let root = tree;
  if (!root) {
    const blob = g(['hash-object', '-w', '--stdin'], bytes);
    const sub = g(['mktree'], `${g(['ls-tree', 'HEAD:checkpoints'])}\n100644 blob ${blob}\t${addName}\n`);
    const lines = g(['ls-tree', 'HEAD']).split('\n').map((l) => (l.endsWith('\tcheckpoints') ? l.replace(/[0-9a-f]{40}/, sub) : l));
    root = g(['mktree'], `${lines.join('\n')}\n`);
  }
  const commit = g(['commit-tree', root, '-p', 'HEAD', '-m', 'plumbing']);
  g(['update-ref', 'refs/heads/main', commit]);
  return commit;
}

test('a mirror of the live dev log verifies, history included', async () => {
  const { dir } = await mirroredRepo();
  const out = verifyDirectory(dir, 'dev', { history: true });
  assert.deepEqual(out.problems, []);
  assert.deepEqual(out.pending, []);
  assert.equal(out.view.checkpoints.length, 1);
});

test('the command line: exit 0 and "every check holds"; exit 1 on a tampered segment', async () => {
  const { dir } = await mirroredRepo();
  const cli = join(HERE, '..', 'tools', 'verify.mjs');
  let r = spawnSync(process.execPath, [cli, '--dir', dir, '--env', 'dev'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /every check holds/);
  writeFileSync(join(dir, 'ct/0.json'), readFileSync(join(dir, 'ct/0.json'), 'utf8').replace('b54fda77', 'c54fda77'));
  r = spawnSync(process.execPath, [cli, '--dir', dir, '--env', 'dev'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL: /);
});

test('the wrong environment fails: a dev mirror judged as prod', async () => {
  const { dir } = await mirroredRepo();
  has(verifyDirectory(dir, 'prod').problems, 'outside the prod fence');
});

test('history: a key that leaves the key set in a later commit is found', async () => {
  const { dir, git } = await mirroredRepo();
  writeFileSync(join(dir, 'jwks.json'), published({ schemaVersion: 1, generatedAt: '2026-10-07T00:00:00Z', keys: [] }));
  git('commit', '-q', '-am', 'drop the key');
  const out = verifyDirectory(dir, 'dev', { history: true });
  has(out.problems, 'psn-dev-2026-2 missing');
});

test('history: a key set that goes back to an older copy in a later commit is found', async () => {
  const { dir, git } = await mirroredRepo();
  const old = JSON.parse(readFileSync(join(dir, 'jwks.json'), 'utf8'));
  writeFileSync(join(dir, 'jwks.json'), published({ ...old, keys: [] }));
  git('commit', '-q', '-am', 'an older copy');
  has(verifyDirectory(dir, 'dev', { history: true }).problems, 'jwks.json went back to an older version');
});

test('history: a file outside the layout in a past commit fails, even when no checkout can hold it (a colon in the name)', async () => {
  const { dir, git } = await mirroredRepo();
  const clean = git('rev-parse', 'HEAD^{tree}');
  const jws = readFileSync(join(dir, 'checkpoints/20261001T002021Z_0.jws'));
  const stray = plumbingCommit(dir, { addName: '2026-10-01T00:20:21Z_0.jws', bytes: jws }).slice(0, 12);
  plumbingCommit(dir, { tree: clean }); // and removed again
  assert.equal(git('status', '--porcelain'), '');
  assert.deepEqual(verifyDirectory(dir, 'dev').problems, [], 'the working tree is clean');
  const out = verifyDirectory(dir, 'dev', { history: true });
  assert.ok(out.problems.includes(`${stray}: a file with an unusual name does not belong in the mirror's layout`), JSON.stringify(out.problems));
});

test('history: a checkpoint file rewritten in a later commit is found', async () => {
  const { dir, git } = await mirroredRepo();
  const path = join(dir, 'checkpoints/20261001T002021Z_0.jws');
  const jws = readFileSync(path, 'latin1');
  writeFileSync(path, `${jws.slice(0, -2)}AA`);
  git('commit', '-q', '-am', 'rewrite');
  has(verifyDirectory(dir, 'dev', { history: true }).problems, 'was rewritten');
});

test('a Software Heritage record of the wrong shape, and a stray file, fail', async () => {
  const { dir } = await mirroredRepo();
  writeFileSync(join(dir, 'checkpoints/20261001T002021Z_0.swh.json'), published({ checkpoint: 'checkpoints/20261001T002021Z_0.jws', origin_url: 'https://github.com/purposesource/transparency-log-dev', snapshot_swhid: 'swh:1:rev:abc', visit_date: '2026-10-06T10:00:00Z', visit_status: 'full', save_request_id: 1, save_request_url: 'https://archive.softwareheritage.org/api/1/origin/save/1/', mirror_commit: 'a'.repeat(40) }));
  mkdirSync(join(dir, 'ct'), { recursive: true });
  writeFileSync(join(dir, 'ct/notes.txt'), 'x');
  const out = verifyDirectory(dir, 'dev');
  has(out.problems, '`snapshot_swhid` is not swh:1:snp:');
  has(out.problems, 'ct/notes.txt does not belong');
});

test('a record with no checkpoint beside it fails', async () => {
  const { dir } = await mirroredRepo();
  writeFileSync(join(dir, 'checkpoints/20261101T000000Z_9.swh.json'), published({ checkpoint: 'checkpoints/20261101T000000Z_9.jws', origin_url: 'https://github.com/purposesource/transparency-log-dev', snapshot_swhid: `swh:1:snp:${'a'.repeat(40)}`, visit_date: '2026-10-06T10:00:00Z', visit_status: 'full', save_request_id: null, save_request_url: null, mirror_commit: 'a'.repeat(40) }));
  has(verifyDirectory(dir, 'dev').problems, 'has no checkpoint beside it');
});

test('core.autocrlf on a Windows checkout cannot rewrite the files: .gitattributes says "* -text" (correction 9)', () => {
  const attributes = readFileSync(join(HERE, '..', '.gitattributes'), 'utf8');
  assert.equal(attributes, '* -text\n');
  const { dir, git } = tempRepo();
  writeFileSync(join(dir, '.gitattributes'), attributes);
  writeFileSync(join(dir, 'a.json'), '{\n  "a": 1\n}\n');
  git('add', '.');
  git('commit', '-q', '-m', 'a');
  execFileSync('git', ['-c', 'core.autocrlf=true', 'checkout', '-q', '--', '.'], { cwd: dir });
  execFileSync('git', ['rm', '-q', '--cached', 'a.json'], { cwd: dir });
  execFileSync('git', ['-c', 'core.autocrlf=true', 'reset', '-q', '--hard'], { cwd: dir });
  assert.equal(readFileSync(join(dir, 'a.json'), 'utf8').includes('\r'), false);
});
