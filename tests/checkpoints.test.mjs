// Checkpoints: colon-free names (correction 1), written once and never rewritten, signed under
// a mirrored key, monotonic in asOf and headSeq, and committing to THIS log (correction 2).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { evaluate } from '../tools/lib/evaluate.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { checkpointName, verifyState } from '../tools/lib/verify-state.mjs';
import { checkpointArtifact, checkpointPayload, devFixtures, issueEntries, jwksFile, makeKey, renderLog, servedFrom, signToken, tsAt, world } from './helpers.mjs';

const run = (mirrored, served, env = 'dev') => evaluate(stateFromFiles(mirrored), servedFrom(served), { env });
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(list)}`);

/** The mirror's files after it adopted `served` (what a first run writes). */
function adopted(served, env = 'dev') {
  const r = run({}, served, env);
  assert.deepEqual(r.incidents, []);
  return Object.fromEntries(r.writes);
}

test('names carry no colon: checkpoints/{YYYYMMDDTHHMMSSZ}_{headSeq}', () => {
  assert.equal(checkpointName('2026-10-01T00:20:21Z', 0), '20261001T002021Z_0');
  assert.equal(checkpointName('2026-10-01T02:20:21+02:00', 12), '20261001T002021Z_12');
  assert.equal(checkpointName('2026-10-01T00:20:21.5Z', 3), '20261001T002021.500Z_3');
  assert.ok(!checkpointName('2026-10-01T00:20:21Z', 0).includes(':'));
});

test('good path: the live dev checkpoint is mirrored once, under its colon-free name', () => {
  const r = run({}, devFixtures());
  assert.equal(r.outcome, 'changed');
  assert.ok(r.writes.has('checkpoints/20261001T002021Z_0.jws'));
  const jws = JSON.parse(devFixtures()['ct/checkpoint-latest.json'].toString()).jws;
  assert.equal(r.writes.get('checkpoints/20261001T002021Z_0.jws').toString('latin1'), jws);
  const again = run(Object.fromEntries(r.writes), devFixtures());
  assert.equal(again.outcome, 'unchanged');
});

test('a checkpoint already mirrored, served with a different token under the same name, is an incident (never rewritten)', () => {
  const w = world();
  const mirrored = adopted(w.files);
  const resigned = signToken(w.key, w.payload); // ECDSA: a second signature of the same body differs
  const served = { ...w.files, 'ct/checkpoint-latest.json': checkpointArtifact(resigned, w.payload) };
  const r = run(mirrored, served);
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'never rewritten');
});

test('a validly signed checkpoint that commits to a different log is an incident (correction 2)', () => {
  const key = makeKey();
  const entries = issueEntries(3);
  const files = renderLog(entries);
  const payload = { ...checkpointPayload(key, entries, 2, tsAt(20)), headSegmentSha256: 'a'.repeat(64) };
  const jws = signToken(key, payload);
  const r = run({}, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(jws, payload), 'jwks.json': jwksFile([key.entry]) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'commits to a different log');
});

test('the head-hash check holds for every mirrored checkpoint as the log grows', () => {
  const w = world({ count: 3 });
  const mirrored = adopted(w.files);
  const grown = renderLog(issueEntries(9));
  const r = run(mirrored, { ...grown, 'ct/checkpoint-latest.json': w.files['ct/checkpoint-latest.json'], 'jwks.json': w.files['jwks.json'] });
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
});

test('when the mirrored copy does not reach headSeq yet the check is pending, and the checkpoint is still kept', () => {
  const key = makeKey();
  const entries = issueEntries(6);
  const payload = checkpointPayload(key, entries, 5, tsAt(20));
  const jws = signToken(key, payload);
  const stale = renderLog(issueEntries(3)); // the edge still serves a shorter log
  const r = run({}, { ...stale, 'ct/checkpoint-latest.json': checkpointArtifact(jws, payload), 'jwks.json': jwksFile([key.entry]) });
  assert.deepEqual(r.incidents, []);
  assert.ok(r.writes.has(`checkpoints/${checkpointName(payload.asOf, 5)}.jws`));
  has(r.warnings, 'does not reach seq 5 yet');
});

test('checkpoints are monotonic: a later asOf may not commit to an earlier head', () => {
  const key = makeKey();
  const entries = issueEntries(6);
  const files = { ...renderLog(entries), 'jwks.json': jwksFile([key.entry]) };
  const p1 = checkpointPayload(key, entries, 5, tsAt(30));
  const mirrored = adopted({ ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p1), p1) });
  const p2 = checkpointPayload(key, entries, 3, tsAt(40));
  const r = run(mirrored, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p2), p2) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'commits to an earlier head');
});

test('two checkpoints at the same asOf are an incident', () => {
  const key = makeKey();
  const entries = issueEntries(6);
  const files = { ...renderLog(entries), 'jwks.json': jwksFile([key.entry]) };
  const p1 = checkpointPayload(key, entries, 3, tsAt(30));
  const mirrored = adopted({ ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p1), p1) });
  const p2 = checkpointPayload(key, entries, 5, tsAt(30));
  const r = run(mirrored, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p2), p2) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'commit at the same asOf');
});

test('good path: a newer checkpoint is added and replaces ct/checkpoint-latest.json; the older stays', () => {
  const key = makeKey();
  const entries = issueEntries(6);
  const files = { ...renderLog(entries), 'jwks.json': jwksFile([key.entry]) };
  const p1 = checkpointPayload(key, entries, 3, tsAt(30));
  const mirrored = adopted({ ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p1), p1) });
  const p2 = checkpointPayload(key, entries, 5, tsAt(40));
  const r = run(mirrored, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p2), p2) });
  assert.equal(r.outcome, 'changed');
  assert.ok(r.writes.has(`checkpoints/${checkpointName(p2.asOf, 5)}.jws`) && r.writes.has('ct/checkpoint-latest.json'));
  const merged = { ...mirrored, ...Object.fromEntries(r.writes) };
  assert.deepEqual(verifyState(stateFromFiles(merged), { env: 'dev' }).problems, []);
});

test('an older checkpoint the mirror never saw (a run missed it) is kept, and ct/checkpoint-latest.json stays the newest', () => {
  const key = makeKey();
  const entries = issueEntries(6);
  const files = { ...renderLog(entries), 'jwks.json': jwksFile([key.entry]) };
  const newer = checkpointPayload(key, entries, 5, tsAt(40));
  const mirrored = adopted({ ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, newer), newer) });
  const older = checkpointPayload(key, entries, 3, tsAt(30));
  const r = run(mirrored, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, older), older) });
  assert.equal(r.outcome, 'changed');
  assert.ok(r.writes.has(`checkpoints/${checkpointName(older.asOf, 3)}.jws`));
  assert.ok(!r.writes.has('ct/checkpoint-latest.json'));
});

test('a checkpoint under a kid the key set does not carry yet is not mirrored this run (a warning, not an incident)', () => {
  const w = world();
  const other = makeKey('psn-dev-2026-8');
  const r = run({}, { ...w.files, 'jwks.json': jwksFile([other.entry]) });
  assert.deepEqual(r.incidents, []);
  has(r.warnings, 'does not carry yet');
  assert.ok(![...r.writes.keys()].some((p) => p.startsWith('checkpoints/')));
});

test('a checkpoint whose signature does not verify under its kid is an incident', () => {
  const w = world();
  const impostor = makeKey(w.key.kid);
  const r = run({}, { ...w.files, 'jwks.json': jwksFile([impostor.entry]) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'does not verify');
});

test('a convenience payload that differs from the signed one is an incident', () => {
  const w = world();
  const r = run({}, { ...w.files, 'ct/checkpoint-latest.json': checkpointArtifact(w.jws, { ...w.payload, headSeq: 1 }) });
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'convenience payload');
});

test('a head entry later than asOf is a note (shown as a warning once), not an incident: the platform takes asOf before it reads the entries', () => {
  const key = makeKey();
  const entries = issueEntries(3);
  const payload = checkpointPayload(key, entries, 2, tsAt(1));
  const files = { ...renderLog(entries), 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, payload), payload), 'jwks.json': jwksFile([key.entry]) };
  const r = run({}, files);
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.incidents, []);
  has(r.warnings, 'later than asOf');
  const state = verifyState(stateFromFiles(Object.fromEntries(r.writes)), { env: 'dev' });
  assert.deepEqual(state.problems, []);
  has(state.notes, 'later than asOf');
  const again = run(Object.fromEntries(r.writes), files);
  assert.ok(!again.warnings.some((w) => w.includes('later than asOf')), 'a note already mirrored is not repeated as a warning every run');
});

test('prod: a checkpoint signed under a psn-dev- key is refused (the S5 fence)', () => {
  const prod = world({ key: makeKey('psn-prod-2026-1') });
  const mirrored = adopted({ ...prod.files, 'ct/checkpoint-latest.json': undefined }, 'prod');
  const dev = world({ key: makeKey('psn-dev-2026-9') });
  const r = run(mirrored, { ...prod.files, 'ct/checkpoint-latest.json': dev.files['ct/checkpoint-latest.json'], 'jwks.json': jwksFile([prod.key.entry, dev.key.entry]) }, 'prod');
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'outside the prod fence');
});

test('an empty prod mirror whose origin serves only psn-dev- keys is "misconfigured" (a setting error), not an incident', () => {
  const dev = world({ key: makeKey('psn-dev-2026-9') });
  const r = run({}, dev.files, 'prod');
  assert.equal(r.outcome, 'misconfigured');
  has(r.incidents, 'every key the origin serves (psn-dev-2026-9) is outside the prod fence');
  has(r.incidents, 'PSN_ENV or PSN_ORIGIN');
  assert.equal(r.writes.size, 0);
  assert.equal(r.evidence.length, 0, 'nothing is kept as evidence');
});

test('the same served keys against a mirror that already holds a log are an incident, never "misconfigured"', () => {
  const dev = world({ key: makeKey('psn-dev-2026-9') });
  const prod = world({ key: makeKey('psn-prod-2026-1') });
  const mirrored = adopted({ ...prod.files, 'ct/checkpoint-latest.json': undefined }, 'prod');
  const r = run(mirrored, dev.files, 'prod');
  assert.equal(r.outcome, 'incident');
});

test('prod: a psn-dev- checkpoint served beside a clean prod key set is an incident, not a quiet skip', () => {
  const dev = world({ key: makeKey('psn-dev-2026-9') });
  const prodKey = makeKey('psn-prod-2026-1');
  const r = run({}, { ...dev.files, 'jwks.json': jwksFile([prodKey.entry]) }, 'prod');
  assert.equal(r.outcome, 'incident');
  has(r.incidents, 'ct/checkpoint-latest.json: signed under psn-dev-2026-9, outside the prod fence');
});

test('no checkpoint published yet (404) is a notice; the log and key set are still mirrored', () => {
  const files = devFixtures();
  delete files['ct/checkpoint-latest.json'];
  const r = run({}, files);
  assert.equal(r.outcome, 'changed');
  has(r.notices, 'no checkpoint is published');
  assert.ok(r.writes.has('ct/0.json') && r.writes.has('jwks.json') && !r.writes.has('ct/checkpoint-latest.json'));
});
