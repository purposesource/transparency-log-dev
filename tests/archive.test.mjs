// The Software Heritage loop (slice 2) against a scripted fake of the API and a real git repo.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { runArchive } from '../tools/archive.mjs';
import { sha256Hex } from '../tools/lib/canonical.mjs';
import { runMirror } from '../tools/mirror.mjs';
import { devFixtures, edgeFetch, ORIGIN, silent, tempRepo } from './helpers.mjs';

const ORIGIN_URL = 'https://github.com/purposesource/transparency-log-dev';
const TOKEN = 'test-token-not-a-secret';
const snapHex = (commit) => sha256Hex(`snapshot-${commit}`).slice(0, 40);

/** A repository the mirror has written its first commit into. */
async function mirroredRepo() {
  const repo = tempRepo();
  await runMirror({ repo: repo.dir, origin: ORIGIN, env: 'dev', fetchImpl: edgeFetch(devFixtures()), commit: true, log: silent });
  return repo;
}

/**
 * A fake Software Heritage. `behaviour.complete(save, polls)` decides when a save finishes;
 * by default after two polls, capturing the repository's HEAD at that moment.
 */
function fakeSwh(dir, behaviour = {}) {
  const calls = [];
  const saves = new Map();
  const snapshots = new Map();
  let nextId = 1000;
  let latestVisit = behaviour.latestVisit ?? null;
  const head = () => execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  const json = (status, body, headers = {}) => new Response(body === undefined ? '' : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const finish = (save) => {
    const commit = behaviour.captures ? behaviour.captures() : head();
    const hex = snapHex(commit);
    snapshots.set(hex, commit);
    if (behaviour.outcome === 'failed') Object.assign(save, { save_task_status: 'failed', visit_status: 'failed' });
    else if (behaviour.outcome === 'empty-snapshot') Object.assign(save, { save_task_status: 'succeeded', visit_status: null, snapshot_swhid: '' });
    else {
      Object.assign(save, { save_task_status: 'succeeded', visit_status: 'full', snapshot_swhid: `swh:1:snp:${hex}`, visit_date: '2026-10-06T10:41:12.123456+00:00' });
      latestVisit = { status: 'full', snapshot: hex, date: save.visit_date, visit: 1 };
    }
  };
  const fn = async (url, init = {}) => {
    const method = init.method ?? 'GET';
    const path = url.slice('https://archive.softwareheritage.org'.length);
    calls.push({ method, path, auth: init.headers?.authorization });
    if (behaviour.status) return json(behaviour.status, { exception: 'x' }, { 'x-ratelimit-reset': '1791282125' });
    if (method === 'GET' && path === `/api/1/origin/${ORIGIN_URL}/visit/latest/?require_snapshot=true`) return latestVisit ? json(200, latestVisit) : json(404, { exception: 'NotFoundExc' });
    if (method === 'POST' && path === `/api/1/origin/save/?visit_type=git&origin_url=${encodeURIComponent(ORIGIN_URL)}`) {
      const save = { id: nextId++, origin_url: ORIGIN_URL, save_request_status: behaviour.rejected ? 'rejected' : 'accepted', save_task_status: 'pending', visit_status: null, snapshot_swhid: '', save_request_date: new Date(behaviour.clock?.() ?? Date.now()).toISOString(), polls: 0 };
      saves.set(save.id, save);
      return json(200, { ...save });
    }
    let m = /^\/api\/1\/origin\/save\/(\d+)\/$/.exec(path);
    if (method === 'GET' && m) {
      const save = saves.get(Number(m[1])) ?? behaviour.knownSaves?.get(Number(m[1]));
      if (!save) return json(404, { exception: 'NotFoundExc' });
      save.polls = (save.polls ?? 0) + 1;
      if (save.save_task_status === 'pending' && save.polls >= (behaviour.pollsToFinish ?? 2)) finish(save);
      return json(200, { ...save });
    }
    m = /^\/api\/1\/snapshot\/([0-9a-f]{40})\/\?branches_from=refs\/heads\/main&branches_count=1$/.exec(path);
    if (method === 'GET' && m) {
      const commit = snapshots.get(m[1]) ?? behaviour.snapshots?.get(m[1]);
      return commit ? json(200, { id: m[1], branches: { 'refs/heads/main': { target: commit, target_type: 'revision' } } }) : json(404, {});
    }
    return json(400, { exception: 'unexpected call in the fake' });
  };
  fn.calls = calls;
  fn.saves = saves;
  fn.snapshots = snapshots;
  fn.setLatestVisit = (v) => {
    latestVisit = v;
  };
  return fn;
}

function clock(start = Date.now()) {
  let t = start;
  return { now: () => t, sleep: async (ms) => { t += ms; } };
}

const archive = (dir, fetchImpl, extra = {}) => {
  const c = clock(extra.start);
  return runArchive({ repo: dir, originUrl: ORIGIN_URL, token: TOKEN, fetchImpl, now: c.now, sleep: c.sleep, commit: true, log: extra.log ?? silent, ...extra.run });
};

test('no token: the save is skipped with a notice and nothing is called', async () => {
  const { dir } = await mirroredRepo();
  const swh = fakeSwh(dir);
  const lines = [];
  const out = await runArchive({ repo: dir, originUrl: ORIGIN_URL, token: '', fetchImpl: swh, log: (l) => lines.push(l) });
  assert.equal(out.status, 'no-token');
  assert.equal(out.red, false);
  assert.equal(swh.calls.length, 0);
  assert.ok(lines[0].startsWith('::notice::'));
});

test('nothing committed to the log yet: nothing to archive, nothing called', async () => {
  const { dir } = tempRepo();
  const swh = fakeSwh(dir);
  const out = await archive(dir, swh);
  assert.equal(out.requests, 0);
  assert.equal(swh.calls.length, 0);
});

test('good path: one save with the Bearer token on every call, polled to a full visit, and the record written beside the checkpoint', async () => {
  const { dir, git } = await mirroredRepo();
  const target = git('rev-parse', 'HEAD');
  const swh = fakeSwh(dir);
  const out = await archive(dir, swh);
  assert.equal(out.status, 'covered');
  assert.equal(out.requests, 1);
  assert.ok(swh.calls.length >= 4);
  assert.ok(swh.calls.every((c) => c.auth === `Bearer ${TOKEN}`), 'the token rides on reads and polls too (correction 7)');
  const record = JSON.parse(readFileSync(join(dir, 'checkpoints/20261001T002021Z_0.swh.json'), 'utf8'));
  assert.deepEqual(Object.keys(record), ['checkpoint', 'origin_url', 'snapshot_swhid', 'visit_date', 'visit_status', 'save_request_id', 'save_request_url', 'mirror_commit']);
  assert.equal(record.snapshot_swhid, `swh:1:snp:${snapHex(target)}`);
  assert.equal(record.visit_status, 'full');
  assert.equal(record.save_request_id, 1000);
  assert.equal(record.mirror_commit, target);
  assert.equal(out.committed, true);
  assert.match(git('log', '-1', '--format=%s'), /^archive: Software Heritage snapshot swh:1:snp:/);
  assert.equal(existsSync(join(dir, 'swh/state.json')), false, 'a save that finished within the run leaves no state behind');
});

test('loop guard: the record commit gets exactly one more save, which adds no record; then nothing', async () => {
  const { dir, git } = await mirroredRepo();
  const swh = fakeSwh(dir);
  await archive(dir, swh);
  const afterRecords = git('rev-parse', 'HEAD');
  const second = await archive(dir, swh);
  assert.equal(second.requests, 1, 'the record commit is a new target');
  assert.equal(second.records.length, 0);
  assert.equal(second.committed, false);
  assert.equal(git('rev-parse', 'HEAD'), afterRecords);
  const third = await archive(dir, swh);
  assert.equal(third.requests, 0, 'covered: no save');
  assert.equal(third.status, 'covered');
});

test('covered already by a full visit (webhook or revisit): no save request; a missing record is written with no request id', async () => {
  const { dir, git } = await mirroredRepo();
  const head = git('rev-parse', 'HEAD');
  const hex = snapHex(head);
  const swh = fakeSwh(dir, { latestVisit: { status: 'full', snapshot: hex, date: '2026-10-06T10:00:00+00:00' }, snapshots: new Map([[hex, head]]) });
  const out = await archive(dir, swh);
  assert.equal(out.requests, 0);
  assert.equal(out.status, 'covered');
  const record = JSON.parse(readFileSync(join(dir, 'checkpoints/20261001T002021Z_0.swh.json'), 'utf8'));
  assert.equal(record.save_request_id, null);
  assert.equal(record.save_request_url, null);
});

test('correction 14: a save that succeeds without capturing the commit gets one new request, and no more than one per run', async () => {
  const { dir, git } = await mirroredRepo();
  const old = git('rev-list', '--max-parents=0', 'HEAD');
  const swh = fakeSwh(dir, { captures: () => old });
  const out = await archive(dir, swh);
  assert.equal(out.requests, 1, 'the one request this run already made counts');
  assert.notEqual(out.status, 'covered');
  const posts = swh.calls.filter((c) => c.method === 'POST').length;
  assert.equal(posts, 1);
});

test('correction 14: a request kept from an earlier run that succeeded without capturing the commit gets its one new request now', async () => {
  const { dir, git } = await mirroredRepo();
  const target = git('rev-parse', 'HEAD');
  const old = git('rev-list', '--max-parents=0', 'HEAD');
  const oldHex = snapHex(old);
  const known = new Map([[77, { id: 77, save_request_status: 'accepted', save_task_status: 'succeeded', visit_status: 'full', snapshot_swhid: `swh:1:snp:${oldHex}`, visit_date: '2026-10-06T09:00:00+00:00' }]]);
  mkdirSync(join(dir, 'swh'), { recursive: true });
  const swh = fakeSwh(dir, { knownSaves: known, snapshots: new Map([[oldHex, old]]) });
  writeFileSync(join(dir, 'swh', 'state.json'), JSON.stringify({ pending: { saveRequestId: 77, target, requestedAt: '2026-10-06T09:00:00Z' } }, null, 2) + '\n');
  git('add', 'swh/state.json');
  git('commit', '-q', '-m', 'archive: save request 77 in flight');
  const out = await archive(dir, swh);
  assert.equal(out.requests, 1);
  assert.equal(out.status, 'covered');
});

test('snapshot_swhid "" is unset: the request stays in flight, and is kept for the next run when the 20 minutes run out', async () => {
  const { dir, git } = await mirroredRepo();
  const swh = fakeSwh(dir, { outcome: 'empty-snapshot', pollsToFinish: 1 });
  const out = await archive(dir, swh);
  assert.notEqual(out.status, 'covered');
  assert.equal(out.committed, true);
  const state = JSON.parse(readFileSync(join(dir, 'swh/state.json'), 'utf8'));
  assert.equal(state.pending.saveRequestId, 1000);
  assert.match(git('log', '-1', '--format=%s'), /is in flight/);
  const polls = swh.calls.filter((c) => c.path === '/api/1/origin/save/1000/').length;
  assert.ok(polls >= 18 && polls <= 21, `polled every 60 s for 20 minutes (${polls} polls)`);
});

test('a kept request is polled by id on the next run, never re-listed and never re-requested while in flight', async () => {
  const { dir } = await mirroredRepo();
  const slow = fakeSwh(dir, { pollsToFinish: 1000 });
  await archive(dir, slow);
  const next = fakeSwh(dir, { knownSaves: slow.saves, pollsToFinish: 0 });
  for (const s of slow.saves.values()) s.polls = 999;
  const out = await archive(dir, next);
  assert.equal(out.requests, 0);
  assert.equal(out.status, 'covered');
  assert.ok(next.calls.every((c) => !c.path.startsWith('/api/1/origin/save/?')), 'no listing and no new request');
  assert.equal(existsSync(join(dir, 'swh/state.json')), true);
  assert.equal(JSON.parse(readFileSync(join(dir, 'swh/state.json'), 'utf8')).pending, null, 'the finished request is cleared');
});

test('a failed save gets one new request', async () => {
  const { dir } = await mirroredRepo();
  const swh = fakeSwh(dir, { outcome: 'failed' });
  const out = await archive(dir, swh);
  assert.equal(swh.calls.filter((c) => c.method === 'POST').length, 1);
  assert.notEqual(out.status, 'covered');
  assert.equal(out.red, false);
});

test('429: stop, no red, try again next run', async () => {
  const { dir } = await mirroredRepo();
  const lines = [];
  const out = await archive(dir, fakeSwh(dir, { status: 429 }), { log: (l) => lines.push(l) });
  assert.equal(out.status, 'rate-limited');
  assert.equal(out.red, false);
  assert.ok(lines.some((l) => l.includes('429')));
});

test('401: red, asking for a new token', async () => {
  const { dir } = await mirroredRepo();
  const lines = [];
  const out = await archive(dir, fakeSwh(dir, { status: 401 }), { log: (l) => lines.push(l) });
  assert.equal(out.red, true);
  assert.ok(lines.some((l) => l.startsWith('::error::') && l.includes('new token')));
});

test('red when no full snapshot holds the commit 24 hours after it was made', async () => {
  const { dir } = await mirroredRepo();
  const out = await archive(dir, fakeSwh(dir, { status: 503 }), { start: Date.now() + 25 * 3600 * 1000 });
  assert.equal(out.red, true);
  assert.equal(out.status, 'stale');
});

test('Software Heritage down within the 24 hours: a warning, not red', async () => {
  const { dir } = await mirroredRepo();
  const out = await archive(dir, fakeSwh(dir, { status: 503 }));
  assert.equal(out.red, false);
  assert.equal(out.status, 'unavailable');
});

test('a snapshot whose main is not in this history (rewritten history) is red, and nothing is repaired', async () => {
  const { dir, git } = await mirroredRepo();
  const head = git('rev-parse', 'HEAD');
  const foreign = 'f'.repeat(40);
  const hex = snapHex(foreign);
  const out = await archive(dir, fakeSwh(dir, { latestVisit: { status: 'full', snapshot: hex, date: '2026-10-06T10:00:00Z' }, snapshots: new Map([[hex, foreign]]) }));
  assert.equal(out.red, true);
  assert.equal(out.status, 'diverged');
  assert.equal(git('rev-parse', 'HEAD'), head);
});

test('a visit without a visit date writes no record (a record that would not verify would stop the next mirror run)', async () => {
  const { dir, git } = await mirroredRepo();
  const head = git('rev-parse', 'HEAD');
  const hex = snapHex(head);
  const out = await archive(dir, fakeSwh(dir, { latestVisit: { status: 'full', snapshot: hex, date: null }, snapshots: new Map([[hex, head]]) }));
  assert.equal(out.records.length, 0);
  assert.equal(existsSync(join(dir, 'checkpoints/20261001T002021Z_0.swh.json')), false);
});

test('a rejected save request is red', async () => {
  const { dir } = await mirroredRepo();
  const out = await archive(dir, fakeSwh(dir, { rejected: true }));
  assert.equal(out.red, true);
});
