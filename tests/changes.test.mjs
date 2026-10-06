// Correction 13: what counts as "changed". New entries, a new checkpoint or a key-set change
// make a commit (and then a Software Heritage save); a new generatedAt alone makes nothing.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { evaluate } from '../tools/lib/evaluate.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { checkpointArtifact, checkpointPayload, devFixtures, issueEntries, jwksFile, makeKey, renderLog, servedFrom, signToken, tsAt } from './helpers.mjs';

const run = (mirrored, served) => evaluate(stateFromFiles(mirrored), servedFrom(served), { env: 'dev' });
const regenerated = (bytes, at) => Buffer.from(bytes.toString().replace(/"generatedAt": "[^"]+"/, `"generatedAt": "${at}"`));

function mirroredDev() {
  return Object.fromEntries(run({}, devFixtures()).writes);
}

test('a new generatedAt on latest.json and jwks.json alone is not a change: no commit', () => {
  const served = devFixtures();
  served['ct/latest.json'] = regenerated(served['ct/latest.json'], '2026-10-06T10:20:00Z');
  served['jwks.json'] = regenerated(served['jwks.json'], '2026-10-06T10:20:00Z');
  const r = run(mirroredDev(), served);
  assert.equal(r.outcome, 'unchanged');
  assert.equal(r.writes.size, 0);
});

test('new entries are a change; latest.json and jwks.json are refreshed to the served bytes in the same commit', () => {
  const key = makeKey();
  const entries = issueEntries(2);
  const before = { ...renderLog(entries, '2026-10-06T00:00:00Z'), 'jwks.json': jwksFile([key.entry], '2026-10-06T00:00:00Z') };
  const mirrored = Object.fromEntries(run({}, before).writes);
  const after = { ...renderLog(issueEntries(3), '2026-10-06T01:00:00Z'), 'jwks.json': jwksFile([key.entry], '2026-10-06T01:00:00Z') };
  const r = run(mirrored, after);
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.changes.map((c) => c.split(' ')[0]).sort(), ['ct/0.json', 'ct/latest.json']);
  assert.ok(r.writes.get('jwks.json').equals(after['jwks.json']), 'the key set is refreshed with the commit');
});

test('a new checkpoint is a change', () => {
  const key = makeKey();
  const entries = issueEntries(3);
  const files = { ...renderLog(entries), 'jwks.json': jwksFile([key.entry]) };
  const mirrored = Object.fromEntries(run({}, files).writes);
  const p = checkpointPayload(key, entries, 2, tsAt(30));
  const r = run(mirrored, { ...files, 'ct/checkpoint-latest.json': checkpointArtifact(signToken(key, p), p) });
  assert.equal(r.outcome, 'changed');
  assert.ok(r.changes.some((c) => c.startsWith('checkpoints/')));
});

test('a key-set change is a change', () => {
  const k1 = makeKey('psn-dev-2026-1');
  const k2 = makeKey('psn-dev-2026-2');
  const files = renderLog(issueEntries(2));
  const mirrored = Object.fromEntries(run({}, { ...files, 'jwks.json': jwksFile([k1.entry]) }).writes);
  const r = run(mirrored, { ...files, 'jwks.json': jwksFile([k1.entry, k2.entry]) });
  assert.equal(r.outcome, 'changed');
  assert.deepEqual(r.changes, ['jwks.json (keys changed)']);
});

test('nothing new at all: no commit', () => {
  const r = run(mirroredDev(), devFixtures());
  assert.equal(r.outcome, 'unchanged');
});
