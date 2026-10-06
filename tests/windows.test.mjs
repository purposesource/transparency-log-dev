// A short read is a stale cache read only while a cache can still hold the older copy: inside
// the file's window, counted from the moment the mirror committed the longer copy (latest.json
// 2 h, ct/{n}.json 26 h, jwks.json 25 h), and never when the served copy was generated later
// than the mirrored one. Otherwise the log shrank, a segment was removed, or a kid left the
// key set, and that is an incident. A segment that stays missing or open while a later one is
// held is an incident 26 hours after the mirror first held the later one.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { evaluate } from '../tools/lib/evaluate.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { fakeClock, hoursBefore, issueEntries, jwksFile, makeKey, ownHashEntry, renderLog, servedFrom } from './helpers.mjs';

const NOW = '2026-10-06T12:00:00Z';
const run = (mirrored, served, clock) => evaluate(stateFromFiles(mirrored), servedFrom(served, NOW), { env: 'dev', clock });
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(list)}`);
const ago = (h) => hoursBefore(NOW, h);

/* ------------------------------------------------------------------ ct/latest.json (2 h) */

const longer = renderLog(issueEntries(5), '2026-10-06T10:00:00Z');
const shorterLatest = (generatedAt) => ({ ...longer, 'ct/latest.json': renderLog(issueEntries(3), generatedAt)['ct/latest.json'] });

test('latest.json served shorter, inside its 2-hour window: a stale read, skipped', () => {
  const r = run(longer, shorterLatest('2026-10-06T09:00:00Z'), fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(1) } }));
  assert.equal(r.outcome, 'unchanged');
  assert.deepEqual(r.incidents, []);
  assert.deepEqual(r.stale, ['ct/latest.json']);
  has(r.notices, 'stale cache read');
});

test('latest.json served shorter, more than 2 hours after the mirror committed the longer copy: an incident (the log shrank)', () => {
  const r = run(longer, shorterLatest('2026-10-06T09:00:00Z'), fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(3) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ct/latest.json as served ends at head seq 2 in segment 0, behind the mirrored copy (head seq 4 in segment 0)');
  has(r.incidents, 'longer than the edge caches this file (2 hours)');
  assert.equal(r.writes.size, 0);
});

test('case 2b: latest.json served shorter with a NEWER generatedAt is an incident at once, even inside the window', () => {
  const r = run(longer, shorterLatest('2026-10-06T11:00:00Z'), fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(0.1) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'generated later than the mirrored copy');
});

test('case 2b with every entry gone (an empty open segment, newer generatedAt): an incident', () => {
  const empty = renderLog([], '2026-10-06T11:00:00Z');
  const r = run(longer, { ...longer, 'ct/latest.json': empty['ct/latest.json'] }, fakeClock({ now: NOW }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ends at head seq none (segment 0)');
});

test('the whole log answering 404: a warning within 2 hours of the mirrored copy, an incident after', () => {
  const inside = run(longer, {}, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(1) } }));
  assert.equal(inside.outcome, 'not-published');
  has(inside.warnings, 'answers 404');
  const after = run(longer, {}, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(5) } }));
  assert.equal(after.outcome, 'incident');
  has(after.incidents, 'the published log is no longer served');
});

/* -------------------------------------------------------- a deleted newest revocation entry */

const base = issueEntries(2);
const withRevocation = renderLog([...base, ownHashEntry(2, base[0].h)], '2026-10-06T10:00:00Z');

test('the newest revocation entry deleted, the open segment re-rendered later: an incident at once', () => {
  const served = renderLog(base, '2026-10-06T11:30:00Z');
  const r = run(withRevocation, served, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(0.5), 'ct/0.json': ago(0.5) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ct/latest.json as served ends at head seq 1');
  has(r.incidents, 'generated later');
});

test('the newest revocation entry deleted, served with the old generatedAt: stale inside the windows, an incident after them', () => {
  const served = renderLog(base, '2026-10-06T10:00:00Z');
  let r = run(withRevocation, served, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(1), 'ct/0.json': ago(1) } }));
  assert.equal(r.outcome, 'unchanged');
  assert.deepEqual(r.stale.sort(), ['ct/0.json', 'ct/latest.json']);
  r = run(withRevocation, served, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(3), 'ct/0.json': ago(3) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ct/latest.json as served ends at head seq 1');
  assert.ok(!r.incidents.some((p) => p.startsWith('ct/0.json')), 'ct/0.json is still inside its 26-hour window');
  r = run(withRevocation, { ...withRevocation, 'ct/0.json': served['ct/0.json'] }, fakeClock({ now: NOW, committed: { 'ct/latest.json': ago(27), 'ct/0.json': ago(27) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ct/0.json as served holds 2 entries, fewer than the 3 the mirror holds');
  has(r.incidents, '(26 hours)');
});

/* ------------------------------------------------------------ ct/{n}.json (26 h), removed */

test('a numbered segment served shorter: stale within 26 hours of the mirrored copy, an incident after', () => {
  const mirrored = renderLog(issueEntries(6));
  const served = { ...mirrored, 'ct/0.json': renderLog(issueEntries(4))['ct/0.json'] };
  const inside = run(mirrored, served, fakeClock({ now: NOW, committed: { 'ct/0.json': ago(25) } }));
  assert.equal(inside.outcome, 'unchanged');
  assert.deepEqual(inside.stale, ['ct/0.json']);
  const after = run(mirrored, served, fakeClock({ now: NOW, committed: { 'ct/0.json': ago(27) } }));
  assert.equal(after.outcome, 'incident');
  has(after.incidents, 'ct/0.json as served holds 4 entries, fewer than the 6 the mirror holds');
});

test('a removed segment: a held ct/{n}.json answering 404 is a warning within 26 hours, an incident after', () => {
  const mirrored = renderLog(issueEntries(3));
  const served = { ...mirrored, 'ct/0.json': 404 };
  const inside = run(mirrored, served, fakeClock({ now: NOW, committed: { 'ct/0.json': ago(2) } }));
  assert.deepEqual(inside.incidents, []);
  has(inside.warnings, 'ct/0.json answers 404');
  const after = run(mirrored, served, fakeClock({ now: NOW, committed: { 'ct/0.json': ago(30) } }));
  assert.equal(after.outcome, 'incident');
  has(after.incidents, 'ct/0.json answers 404, and the mirror has held it since');
  has(after.incidents, 'a published segment is no longer served');
});

/* ---------------------------------------------------------------- rollover (26 h) */

test('rollover overdue: segment 0 still served open 26 hours after the mirror first held segment 1 is an incident', () => {
  const before = renderLog(issueEntries(9998));
  const after = renderLog(issueEntries(10003));
  const mirrored = { 'ct/0.json': before['ct/0.json'], 'ct/latest.json': after['ct/latest.json'] };
  const served = { 'ct/latest.json': after['ct/latest.json'], 'ct/0.json': before['ct/0.json'], 'ct/1.json': 404 };
  const waiting = run(mirrored, served, fakeClock({ now: NOW, held: { 1: ago(3) } }));
  assert.deepEqual(waiting.incidents, []);
  has(waiting.warnings, 'its closed copy is not served yet');
  const overdue = run(mirrored, served, fakeClock({ now: NOW, held: { 1: ago(27) } }));
  assert.equal(overdue.outcome, 'incident');
  has(overdue.incidents, 'segment 0 is still served open (9998 entries)');
  has(overdue.incidents, 'its closed copy is missing');
});

test('a segment never served while a later one is held: an incident 26 hours after the mirror first held the later one', () => {
  const after = renderLog(issueEntries(10003));
  const mirrored = { 'ct/latest.json': after['ct/latest.json'] };
  const served = { 'ct/latest.json': after['ct/latest.json'], 'ct/0.json': 404, 'ct/1.json': 404 };
  assert.deepEqual(run(mirrored, served, fakeClock({ now: NOW, held: { 1: ago(10) } })).incidents, []);
  const overdue = run(mirrored, served, fakeClock({ now: NOW, held: { 1: ago(40) } }));
  assert.equal(overdue.outcome, 'incident');
  has(overdue.incidents, 'segment 0 is still not served');
});

test('the rollover that completes in time is adopted with no incident', () => {
  const before = renderLog(issueEntries(9998));
  const after = renderLog(issueEntries(10003));
  const mirrored = { 'ct/0.json': before['ct/0.json'], 'ct/latest.json': after['ct/latest.json'] };
  const r = run(mirrored, after, fakeClock({ now: NOW, held: { 1: ago(27) } }));
  assert.deepEqual(r.incidents, []);
  assert.equal(r.outcome, 'changed');
  assert.ok(r.writes.has('ct/0.json') && r.writes.has('ct/1.json'));
});

/* ----------------------------------------------------------------- jwks.json (25 h) */

const k1 = makeKey('psn-dev-2026-1');
const k2 = makeKey('psn-dev-2026-2');
const log = renderLog(issueEntries(2));
const keysMirrored = { ...log, 'jwks.json': jwksFile([k1.entry, k2.entry], '2026-10-06T10:00:00Z') };

test('case 3a: every kid removed, same generatedAt: stale within 25 hours of the mirrored set, an incident after', () => {
  const served = { ...log, 'jwks.json': jwksFile([], '2026-10-06T10:00:00Z') };
  const inside = run(keysMirrored, served, fakeClock({ now: NOW, committed: { 'jwks.json': ago(24) } }));
  assert.equal(inside.outcome, 'unchanged');
  assert.deepEqual(inside.stale, ['jwks.json']);
  const after = run(keysMirrored, served, fakeClock({ now: NOW, committed: { 'jwks.json': ago(26) } }));
  assert.equal(after.outcome, 'incident');
  has(after.incidents, 'jwks.json as served is an older version of the mirrored key set (psn-dev-2026-1 missing, psn-dev-2026-2 missing)');
  has(after.incidents, '(25 hours)');
});

test('case 3b: a kid removed with a NEWER generatedAt is an incident at once', () => {
  const served = { ...log, 'jwks.json': jwksFile([k1.entry], '2026-10-07T00:00:00Z') };
  const r = run(keysMirrored, served, fakeClock({ now: NOW, committed: { 'jwks.json': ago(0.2) } }));
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'psn-dev-2026-2 missing');
  has(r.incidents, 'generated later than the mirrored copy');
});

test('a key set served with a 404 after 25 hours: an incident; within them: a warning', () => {
  const served = { ...log, 'jwks.json': 404 };
  assert.deepEqual(run(keysMirrored, served, fakeClock({ now: NOW, committed: { 'jwks.json': ago(1) } })).incidents, []);
  has(run(keysMirrored, served, fakeClock({ now: NOW, committed: { 'jwks.json': ago(26) } })).incidents, 'the key set is no longer served');
});

test('a copy the mirror wrote but has not committed yet counts as committed just now', () => {
  const r = run(longer, shorterLatest('2026-10-06T09:00:00Z'), fakeClock({ now: NOW }));
  assert.equal(r.outcome, 'unchanged');
  assert.deepEqual(r.stale, ['ct/latest.json']);
});
