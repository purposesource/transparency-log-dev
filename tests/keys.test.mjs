// The key set only grows (correction 5): no kid disappears, no key material changes, a new kid
// is flagged; an older copy served from a cache is a stale read.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { compareKeySets } from '../tools/lib/keys.mjs';
import { evaluate } from '../tools/lib/evaluate.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { jwksFile, makeKey, servedFrom, world } from './helpers.mjs';

const a = makeKey('psn-dev-2026-1');
const b = makeKey('psn-dev-2026-2');
const set = (...keys) => ({ schemaVersion: 1, keys: keys.map((k) => structuredClone(k)) });
const retired = (k) => ({ ...k, 'psn:status': 'retired', 'psn:validityWindow': { notBefore: k['psn:validityWindow'].notBefore, notAfter: '2026-10-05T00:00:00Z' } });

test('the same keys are "same"', () => {
  assert.equal(compareKeySets(set(a.entry), set(a.entry)).verdict, 'same');
});

test('a new kid is an advance, and is flagged', () => {
  const r = compareKeySets(set(a.entry), set(a.entry, b.entry));
  assert.equal(r.verdict, 'advance');
  assert.ok(r.notices.some((n) => n.includes('a new key appears, psn-dev-2026-2')));
});

test('a retirement (standing moves forward) is an advance', () => {
  assert.equal(compareKeySets(set(a.entry), set(retired(a.entry))).verdict, 'advance');
});

test('changed key material is an incident', () => {
  const r = compareKeySets(set(a.entry), set({ ...a.entry, x: b.entry.x, y: b.entry.y }));
  assert.equal(r.verdict, 'incident');
  assert.ok(r.problems[0].includes('key material of psn-dev-2026-1 changed'));
});

test('a kid that disappears while the set also changed otherwise is an incident', () => {
  const r = compareKeySets(set(a.entry), set(b.entry));
  assert.equal(r.verdict, 'incident');
  assert.ok(r.problems[0].includes('psn-dev-2026-1 disappeared'));
});

test('an older copy of the set (a kid missing, nothing newer) is "stale", naming what makes it older', () => {
  const missing = compareKeySets(set(a.entry, b.entry), set(a.entry));
  assert.equal(missing.verdict, 'stale');
  assert.deepEqual(missing.gone, ['psn-dev-2026-2']);
  const back = compareKeySets(set(retired(a.entry)), set(a.entry));
  assert.equal(back.verdict, 'stale');
  assert.deepEqual(back.backwards, ['psn-dev-2026-1']);
});

test('a changed notBefore (a backdated key) is an incident, not an advance', () => {
  const backdated = { ...a.entry, 'psn:validityWindow': { notBefore: '2020-01-01T00:00:00Z', notAfter: null } };
  const r = compareKeySets(set(a.entry), set(backdated));
  assert.equal(r.verdict, 'incident');
  assert.ok(r.problems[0].includes('the validity window of psn-dev-2026-1 now opens at a different time'));
  const later = { ...a.entry, 'psn:validityWindow': { notBefore: '2026-09-15T00:00:00Z', notAfter: null } };
  assert.equal(compareKeySets(set(a.entry), set(later)).verdict, 'incident');
});

test('end to end: a backdated key is an incident and the key set is not committed', () => {
  const w = world();
  const mirrored = Object.fromEntries(evaluate(stateFromFiles({}), servedFrom(w.files), { env: 'dev' }).writes);
  const backdated = { ...w.key.entry, 'psn:validityWindow': { notBefore: '2020-01-01T00:00:00Z', notAfter: null } };
  const r = evaluate(stateFromFiles(mirrored), servedFrom({ ...w.files, 'jwks.json': jwksFile([backdated]) }), { env: 'dev' });
  assert.equal(r.outcome, 'incident');
  assert.equal(r.writes.size, 0);
});

test('end to end: a key-set incident stops the run and moves nothing', () => {
  const w = world();
  const first = evaluate(stateFromFiles({}), servedFrom(w.files), { env: 'dev' });
  const mirrored = Object.fromEntries(first.writes);
  const swapped = { ...w.key.entry, x: b.entry.x, y: b.entry.y };
  const r = evaluate(stateFromFiles(mirrored), servedFrom({ ...w.files, 'jwks.json': jwksFile([swapped]) }), { env: 'dev' });
  assert.equal(r.outcome, 'incident');
  assert.equal(r.writes.size, 0);
});
