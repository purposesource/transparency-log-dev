// The growth rules of plan §2 with correction 3: closed segments never change, the open
// segment only extends, seq runs on, the chain recomputes, the entry rules hold across the
// log; a strict prefix is a stale read and is skipped, only a non-prefix is an incident.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderLatest, renderSegment, sha256Hex } from '../tools/lib/canonical.mjs';
import { evaluate } from '../tools/lib/evaluate.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { issueEntries, ownHashEntry, renderLog, servedFrom } from './helpers.mjs';

const run = (mirrored, served) => evaluate(stateFromFiles(mirrored), servedFrom(served), { env: 'dev' });
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(list)}`);
const latestOf = (entries, extra = {}) => renderLatest({ schemaVersion: 1, segment: 0, startSeq: 0, prevSegmentSha256: null, entries, generatedAt: '2026-10-06T00:00:00Z', closed: false, ...extra });
const seg0Of = (entries) => renderSegment({ schemaVersion: 1, segment: 0, startSeq: 0, prevSegmentSha256: null, entries });

test('good path: a log that grew is adopted, both copies of the open segment', () => {
  const r = run(renderLog(issueEntries(3)), renderLog(issueEntries(5)));
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
  assert.ok(r.writes.has('ct/0.json') && r.writes.has('ct/latest.json'));
  assert.equal(r.summary.headSeq, 4);
});

test('good path: a log with a closed segment and a chained second one is adopted from nothing', () => {
  const r = run({}, renderLog(issueEntries(10003)));
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
  assert.ok(r.writes.has('ct/1.json'));
});

test('a strict prefix of what is mirrored is a stale read: skipped, no incident (correction 3)', () => {
  const r = run(renderLog(issueEntries(5)), renderLog(issueEntries(3)));
  assert.equal(r.outcome, 'unchanged');
  assert.deepEqual(r.incidents, []);
  has(r.notices, 'stale cache read');
});

test('a numbered segment that lags latest.json by a day is not an incident', () => {
  const now = renderLog(issueEntries(6));
  const r = run(renderLog(issueEntries(4)), { ...now, 'ct/0.json': renderLog(issueEntries(2))['ct/0.json'] });
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
  assert.ok(r.writes.has('ct/latest.json') && !r.writes.has('ct/0.json'));
});

test('a rewritten entry (not a prefix) is an incident', () => {
  const entries = issueEntries(4);
  entries[1] = { ...entries[1], h: sha256Hex('another') };
  const r = run(renderLog(issueEntries(3)), renderLog(entries));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'disagree at seq 1');
  assert.equal(r.writes.size, 0);
});

test('a removed entry (the log shrank and the rest moved up) is an incident', () => {
  const shifted = issueEntries(5).filter((e) => e.seq !== 2).map((e, i) => ({ ...e, seq: i }));
  const r = run(renderLog(issueEntries(5)), renderLog(shifted));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'disagree at seq 2');
});

test('a closed segment served with different bytes is an incident', () => {
  const mirrored = renderLog(issueEntries(10002));
  const entries = issueEntries(10002);
  entries[7] = { ...entries[7], h: sha256Hex('changed') };
  const served = { ...mirrored, 'ct/0.json': renderLog(entries)['ct/0.json'] };
  const r = run(mirrored, served);
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'disagree at seq 7');
});

test('a broken prevSegmentSha256 chain is an incident', () => {
  const files = renderLog(issueEntries(10002));
  const seg1 = JSON.parse(files['ct/1.json'].toString());
  seg1.prevSegmentSha256 = 'f'.repeat(64);
  const latest = JSON.parse(files['ct/latest.json'].toString());
  latest.prevSegmentSha256 = 'f'.repeat(64);
  const r = run({}, { ...files, 'ct/1.json': renderSegment(seg1), 'ct/latest.json': renderLatest(latest) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'the chain does not recompute');
});

test('a gap in seq is an incident', () => {
  const entries = issueEntries(4);
  entries[3] = { ...entries[3], seq: 4 };
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'no gap');
});

test('a timestamp earlier than the entry before it is an incident', () => {
  const entries = issueEntries(3);
  entries[2] = { ...entries[2], ts: '2026-09-01T00:00:00Z' };
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'earlier than the entry before it');
});

test('a hash logged twice is an incident', () => {
  const entries = issueEntries(3);
  entries[2] = { ...entries[2], h: entries[0].h };
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'already logged at seq 0');
});

test('an issue entry with a ref is an incident', () => {
  const entries = issueEntries(2);
  entries[1] = { ...entries[1], ref: entries[0].h };
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'must be null');
});

test('a revocation naming no earlier entry is an incident (unknown, or later)', () => {
  const entries = [...issueEntries(2), ownHashEntry(2, 'e'.repeat(64))];
  let r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'names no earlier entry');
  const later = [...issueEntries(2)];
  later.push(ownHashEntry(2, sha256Hex('entry-3')));
  later.push({ ...issueEntries(4)[3] });
  r = run({}, { 'ct/latest.json': latestOf(later), 'ct/0.json': seg0Of(later) });
  has(r.incidents, 'names no earlier entry');
});

test('a revocation whose h is not its own hash is an incident', () => {
  const entries = [...issueEntries(2), { ...ownHashEntry(2, sha256Hex('entry-0')), h: 'd'.repeat(64) }];
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, "entry's own members");
});

test('good path: revoke, status and the coming record kind, each naming an earlier entry', () => {
  const base = issueEntries(3);
  const entries = [...base, ownHashEntry(3, base[0].h, 'revoke'), ownHashEntry(4, base[1].h, 'status'), ownHashEntry(5, base[2].h, 'record', 'license-status')];
  const r = run({}, { 'ct/latest.json': latestOf(entries), 'ct/0.json': seg0Of(entries) });
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
});

test('rollover: latest.json moved to segment 1 while /ct/0.json is still the short open copy and /ct/1.json is a cached 404', () => {
  const before = renderLog(issueEntries(9998));
  const after = renderLog(issueEntries(10003));
  const r = run(before, { 'ct/latest.json': after['ct/latest.json'], 'ct/0.json': before['ct/0.json'], 'ct/1.json': 404 });
  assert.deepEqual(r.incidents, []);
  assert.equal(r.outcome, 'changed');
  has(r.warnings, 'its closed copy is not served yet');
  has(r.warnings, 'ct/1.json answers 404');
});

test('rollover completes: the closed copy arrives and the chain is checked', () => {
  const before = renderLog(issueEntries(9998));
  const after = renderLog(issueEntries(10003));
  const r = run(before, after);
  assert.deepEqual(r.incidents, []);
  assert.ok(r.writes.has('ct/0.json') && r.writes.has('ct/1.json'));
  assert.ok(!r.warnings.some((w) => w.includes('closed copy')));
});

test('a 5xx or no answer skips the run, green, with a warning; nothing is judged', () => {
  const files = renderLog(issueEntries(3));
  const r = run({}, { ...files, 'ct/0.json': 503 });
  assert.equal(r.outcome, 'unreadable');
  assert.equal(r.writes.size, 0);
  has(r.warnings, 'says nothing about the log');
});

test('the mirror must be clean before anything is added: a broken mirror stops the run', () => {
  const mirrored = renderLog(issueEntries(3));
  mirrored['ct/0.json'] = Buffer.from(mirrored['ct/0.json'].toString().replace('"seq": 1', '"seq": 7'));
  const r = run(mirrored, renderLog(issueEntries(4)));
  assert.equal(r.outcome, 'mirror-broken');
});
