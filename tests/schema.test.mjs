// The contracts written as code, the no-names rule, and the published byte form. One failing
// case per rule.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { published, renderSegment } from '../tools/lib/canonical.mjs';
import { checkpointPayloadProblems, entryProblems, hasDuplicateMember, isDateTime, jwksProblems, parseJson, piiProblems, segmentProblems } from '../tools/lib/schema.mjs';
import { readFile } from '../tools/lib/verify-state.mjs';
import { devFixtures, issueEntries, makeKey, ownHashEntry } from './helpers.mjs';

const dev = devFixtures();
const doc0 = () => JSON.parse(dev['ct/0.json'].toString('utf8'));
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected a problem containing "${fragment}", got ${JSON.stringify(list)}`);

test('the four live dev files pass their contracts, the no-names rule and the byte form', () => {
  for (const [path, kind] of [['ct/0.json', 'numbered'], ['ct/latest.json', 'latest'], ['ct/checkpoint-latest.json', 'checkpoint-artifact'], ['jwks.json', 'jwks']]) {
    const r = readFile(dev[path], path, kind, { env: 'dev' });
    assert.deepEqual([...r.schema, ...r.pii, ...r.form], [], path);
  }
});

test('segment: a required member missing', () => {
  const d = doc0();
  delete d.prevSegmentSha256;
  has(segmentProblems(d, 'f', 'numbered'), 'has no `prevSegmentSha256`');
});

test('segment: a member the contract does not define (additionalProperties false)', () => {
  has(segmentProblems({ ...doc0(), subject: 'x' }, 'f', 'numbered'), 'carries a member, which ct-segment.v1 does not define');
  assert.ok(segmentProblems({ ...doc0(), JohnSmith: 'x' }, 'f', 'numbered').every((p) => !p.includes('John')), 'the name of an unknown member is never repeated');
});

test('segment: schemaVersion other than 1', () => {
  has(segmentProblems({ ...doc0(), schemaVersion: 2 }, 'f', 'numbered'), '`schemaVersion` is not 1');
});

test('segment: startSeq that is not segment × 10000', () => {
  has(segmentProblems({ ...doc0(), segment: 1, startSeq: 5, prevSegmentSha256: 'a'.repeat(64) }, 'f', 'numbered'), 'not segment ×');
});

test('segment: segment 0 with a predecessor, segment 1 without one', () => {
  has(segmentProblems({ ...doc0(), prevSegmentSha256: 'a'.repeat(64) }, 'f', 'numbered'), 'segment 0 has no predecessor');
  has(segmentProblems({ ...doc0(), segment: 1, startSeq: 10000, entries: [] }, 'f', 'numbered'), "must name its predecessor's hash");
});

test('segment: more than 10000 entries', () => {
  has(segmentProblems({ ...doc0(), entries: issueEntries(10001) }, 'f', 'numbered'), 'more than the 10000');
});

test('segment: seq not running on from startSeq', () => {
  const entries = issueEntries(3);
  entries[2] = { ...entries[2], seq: 5 };
  has(segmentProblems({ ...doc0(), entries }, 'f', 'numbered'), 'run on from startSeq with no gap');
});

test('latest: closed must follow from the entry count, and the open segment carries generatedAt and closed', () => {
  const latest = JSON.parse(dev['ct/latest.json'].toString('utf8'));
  has(segmentProblems({ ...latest, closed: true }, 'f', 'latest'), '`closed` does not follow');
  const { generatedAt, ...noGen } = latest;
  has(segmentProblems(noGen, 'f', 'latest'), 'carries `generatedAt`');
});

test('entry: an extra member, a bad h, a typ and a kind the contract does not define, a ts that is not a date-time', () => {
  const e = issueEntries(1)[0];
  has(entryProblems({ ...e, email: 'x' }, 'e'), 'carries a member');
  has(entryProblems({ ...e, h: 'ABC' }, 'e'), '`h` is not 64 lowercase hex');
  has(entryProblems({ ...e, typ: 'person' }, 'e'), '`typ` is not one');
  has(entryProblems({ ...e, kind: 'edit' }, 'e'), '`kind` is not one');
  has(entryProblems({ ...e, ts: 'yesterday' }, 'e'), '`ts` is not an RFC 3339');
});

test('entry: issue implies ref null', () => {
  has(entryProblems({ ...issueEntries(1)[0], ref: 'b'.repeat(64) }, 'e'), 'must be null');
});

test('entry: revoke and status name the original in ref, and carry their own hash', () => {
  const original = issueEntries(1)[0];
  for (const kind of ['revoke', 'status']) {
    const good = ownHashEntry(1, original.h, kind);
    assert.deepEqual(entryProblems(good, 'e'), []);
    has(entryProblems({ ...good, ref: null }, 'e'), "must name the original entry's hash");
    has(entryProblems({ ...good, h: 'c'.repeat(64) }, 'e'),'is not the SHA-256 of the entry\'s own members');
    has(entryProblems({ ...good, h: good.ref }, 'e'), '`h` equals `ref`');
  }
});

test('entry: the coming `record` kind is accepted (plan correction 4) under the same rules as a revocation', () => {
  const original = issueEntries(1)[0];
  const record = ownHashEntry(1, original.h, 'record', 'license-status');
  assert.deepEqual(entryProblems(record, 'e'), []);
  has(entryProblems({ ...record, ref: null }, 'e'), "must name the original entry's hash");
});

test('date-time: RFC 3339 only, real dates only, no leap second', () => {
  assert.equal(isDateTime('2026-10-01T00:20:21Z'), true);
  assert.equal(isDateTime('2024-01-17T11:44:37.846370+00:00'), true);
  assert.equal(isDateTime('2026-02-30T00:00:00Z'), false);
  assert.equal(isDateTime('2026-10-01 00:20:21Z'), false);
  assert.equal(isDateTime('2026-10-01T23:59:60Z'), false);
});

test('no names: an email-shaped value is refused', () => {
  has(piiProblems({ a: { b: 'someone@example.org' } }), 'email-shaped');
});

test('no names: a name-shaped value is refused', () => {
  has(piiProblems({ entries: [{ note: 'Jane Doe' }] }), 'name-shaped');
});

test('no names: a member name that is an address is refused, and messages never quote it', () => {
  const problems = piiProblems({ 'jane@example.org': 1 });
  has(problems, 'email- or name-shaped');
  assert.ok(problems.every((p) => !p.includes('jane')));
});

test('no names: the live dev files hold nothing name- or email-shaped', () => {
  for (const b of Object.values(dev)) assert.deepEqual(piiProblems(JSON.parse(b.toString('utf8'))), []);
});

test('byte form: re-indented, CRLF, or without the trailing newline is not the published form', () => {
  const d = doc0();
  const variants = [
    Buffer.from(JSON.stringify(d, null, 4) + '\n'),
    Buffer.from((JSON.stringify(d, null, 2) + '\n').replaceAll('\n', '\r\n')),
    Buffer.from(JSON.stringify(d, null, 2)),
  ];
  for (const v of variants) has(readFile(v, 'ct/0.json', 'numbered').form, 'published byte form');
  assert.deepEqual(readFile(renderSegment(d), 'ct/0.json', 'numbered').form, []);
});

test('parsing: a member named twice, a byte-order mark, invalid UTF-8', () => {
  assert.equal(hasDuplicateMember('{"a":1,"b":{"c":2,"c":3}}'), true);
  assert.equal(hasDuplicateMember('{"a":"{\\"a\\":1}","b":[{"a":1},{"a":2}]}'), false);
  assert.match(parseJson(Buffer.from('{"a":1,"a":2}')).problem, /twice/);
  assert.match(parseJson(Buffer.from('﻿{}')).problem, /byte-order mark/);
  assert.match(parseJson(Buffer.from([0x7b, 0xff, 0x7d])).problem, /UTF-8/);
});

test('checkpoint payload: ct-checkpoint.v1 members, types, and headSegment = headSeq ÷ 10000', () => {
  const p = { asOf: '2026-10-01T00:20:21Z', headSeq: 0, headSegment: 0, headSegmentSha256: 'a'.repeat(64), kid: 'psn-dev-2026-2', iss: 'https://dev-api.purposesource.org' };
  assert.deepEqual(checkpointPayloadProblems(p, 'p'), []);
  has(checkpointPayloadProblems({ ...p, note: 'x' }, 'p'), 'carries a member');
  has(checkpointPayloadProblems({ ...p, headSegment: 1 }, 'p'), 'not the segment');
  has(checkpointPayloadProblems({ ...p, kid: 'psn-preview-2026-1' }, 'p'), "kid` does not match");
  has(checkpointPayloadProblems({ ...p, iss: 'https://jane:pw@example.org' }, 'p'), 'not an https origin');
  const { asOf, ...noAsOf } = p;
  has(checkpointPayloadProblems(noAsOf, 'p'), 'has no `asOf`');
});

test('jwks: the published key members only, P-256 points, one entry per kid, no sandbox marker, inside the fence', () => {
  const k = makeKey('psn-dev-2026-9').entry;
  assert.deepEqual(jwksProblems({ schemaVersion: 1, keys: [k] }, 'jwks.json', 'dev'), []);
  has(jwksProblems({ keys: [{ ...k, d: 'secret' }] }, 'jwks.json', 'dev'), 'carries a member, which a published key does not carry');
  has(jwksProblems({ keys: [k, k] }, 'jwks.json', 'dev'), 'appears more than once');
  has(jwksProblems({ keys: [{ ...k, x: 'abc' }] }, 'jwks.json', 'dev'), '`x` is not 32 bytes');
  has(jwksProblems({ sandbox: true, keys: [k] }, 'jwks.json', 'dev'), 'carries `sandbox`');
  has(jwksProblems({ keys: [k] }, 'jwks.json', 'prod'), 'outside the prod fence');
  has(jwksProblems({ keys: [{ ...k, 'psn:status': 'lost' }] }, 'jwks.json', 'dev'), '`psn:status` is not');
  has(jwksProblems({ keys: [{ ...k, crv: 'P-384' }] }, 'jwks.json', 'dev'), '`crv` is not P-256');
});

test('jwks: coordinates that are not a point on the curve', () => {
  const k = makeKey('psn-dev-2026-9').entry;
  const bad = { ...k, y: Buffer.alloc(32, 1).toString('base64url') };
  has(jwksProblems({ keys: [bad] }, 'jwks.json', 'dev'), 'not a point on P-256');
});

test('published() is the platform form', () => {
  assert.equal(published({ a: 1, b: [] }).toString(), '{\n  "a": 1,\n  "b": []\n}\n');
});
