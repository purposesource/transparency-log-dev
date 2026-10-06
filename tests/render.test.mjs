// Plan correction 2: a checkpoint's headSegmentSha256 is the SHA-256 of the head segment cut at
// headSeq and re-rendered exactly as the platform renders it. The specification does not define
// that byte form, so it is pinned here to the first signed dev checkpoint (test vectors).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderCut, renderLatest, renderSegment, sha256Hex } from '../tools/lib/canonical.mjs';
import { readToken } from '../tools/lib/verify-state.mjs';
import { devFixtures, issueEntries, renderLog } from './helpers.mjs';

const dev = devFixtures();
const parse = (b) => JSON.parse(b.toString('utf8'));

test('vector: the served dev /ct/0.json hashes to the dev checkpoint\'s headSegmentSha256', () => {
  const ckp = parse(dev['ct/checkpoint-latest.json']);
  const token = readToken(ckp.jws, 'jws');
  assert.deepEqual(token.problems, []);
  assert.equal(token.payload.headSeq, 0);
  assert.equal(token.payload.headSegment, 0);
  assert.equal(sha256Hex(dev['ct/0.json']), token.payload.headSegmentSha256);
  assert.equal(token.payload.headSegmentSha256, 'da9c24cc2dae9b9ef65b5d92f2ac804aaf9f3f761435d66777188cd7734be415');
});

test('vector: re-rendering the served /ct/0.json gives its exact bytes (322 bytes, LF, one trailing newline)', () => {
  const doc = parse(dev['ct/0.json']);
  const bytes = renderSegment(doc);
  assert.ok(bytes.equals(dev['ct/0.json']));
  assert.equal(bytes.length, 322);
  assert.equal(bytes.includes(0x0d), false);
  assert.equal(bytes[bytes.length - 1], 0x0a);
});

test('vector: /ct/latest.json is the same body plus generatedAt and closed, and re-renders exactly', () => {
  const doc = parse(dev['ct/latest.json']);
  assert.ok(renderLatest(doc).equals(dev['ct/latest.json']));
});

test('vector: the cut of latest.json at headSeq 0 is the checkpointed segment', () => {
  const doc = parse(dev['ct/latest.json']);
  assert.equal(sha256Hex(renderCut(doc, 0)), 'da9c24cc2dae9b9ef65b5d92f2ac804aaf9f3f761435d66777188cd7734be415');
});

test('a cut stays true as the segment grows: entries after headSeq do not move the hash', () => {
  const before = renderLog(issueEntries(3))['ct/0.json'];
  const grown = parse(renderLog(issueEntries(7))['ct/0.json']);
  assert.ok(renderCut(grown, 2).equals(before));
});

test('a different cut gives a different hash', () => {
  const grown = parse(renderLog(issueEntries(7))['ct/0.json']);
  assert.notEqual(sha256Hex(renderCut(grown, 2)), sha256Hex(renderCut(grown, 3)));
});
