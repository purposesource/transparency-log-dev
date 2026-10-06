// ES256 with node:crypto, the checkpoint token profile, and the environment fence.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { jcs } from '../tools/lib/canonical.mjs';
import { parseCompact, verifyEs256 } from '../tools/lib/jws.mjs';
import { stateFromFiles } from '../tools/lib/state.mjs';
import { readToken, verifyState } from '../tools/lib/verify-state.mjs';
import { devFixtures, makeKey, signToken, world } from './helpers.mjs';

const dev = devFixtures();
const devJws = JSON.parse(dev['ct/checkpoint-latest.json'].toString('utf8')).jws;
const devKey = JSON.parse(dev['jwks.json'].toString('utf8')).keys[0];
const has = (list, fragment) => assert.ok(list.some((p) => p.includes(fragment)), `expected "${fragment}" in ${JSON.stringify(list)}`);

test('the live dev checkpoint verifies under the live dev key set', () => {
  const t = parseCompact(devJws);
  assert.equal(t.problem, undefined);
  assert.equal(verifyEs256(t.signingInput, t.signature, devKey), true);
});

test('a token whose payload was altered does not verify', () => {
  const [h, , s] = devJws.split('.');
  const t = parseCompact(devJws);
  const forged = Buffer.from(jcs({ ...t.payload, headSeq: 1 })).toString('base64url');
  const f = parseCompact(`${h}.${forged}.${s}`);
  assert.equal(verifyEs256(f.signingInput, f.signature, devKey), false);
});

test('a token does not verify under another key', () => {
  const t = parseCompact(devJws);
  assert.equal(verifyEs256(t.signingInput, t.signature, makeKey().entry), false);
});

test('a signature that is not 64 raw bytes is refused', () => {
  const t = parseCompact(devJws);
  assert.equal(verifyEs256(t.signingInput, t.signature.subarray(0, 63), devKey), false);
});

test('base64url must be canonical and unpadded', () => {
  const [h, p, s] = devJws.split('.');
  assert.match(parseCompact(`${h}=.${p}.${s}`).problem, /base64url/);
  assert.match(parseCompact(`${h}.${p}`).problem, /three/);
});

test('the payload must be its own RFC 8785 text (what ct-checkpoint.v1 says is signed)', () => {
  const key = makeKey();
  const header = Buffer.from(jcs({ alg: 'ES256', kid: key.kid, typ: 'application/psn-ct-checkpoint+jws' })).toString('base64url');
  const loose = Buffer.from('{ "asOf": "2026-10-01T00:00:00Z" }').toString('base64url');
  assert.match(parseCompact(`${header}.${loose}.AAAA`).problem, /RFC 8785/);
});

test('the header must be the checkpoint profile: alg ES256, typ, a kid; alg none is refused', () => {
  const key = makeKey();
  const payload = { asOf: '2026-10-01T00:00:00Z', headSeq: 0, headSegment: 0, headSegmentSha256: 'a'.repeat(64) };
  has(readToken(signToken(key, payload, { alg: 'none', kid: key.kid, typ: 'application/psn-ct-checkpoint+jws' }), 't').problems, 'alg is not ES256');
  has(readToken(signToken(key, payload, { alg: 'ES256', kid: key.kid, typ: 'JWT' }), 't').problems, 'typ is not');
  has(readToken(signToken(key, payload, { alg: 'ES256', kid: key.kid, typ: 'application/psn-ct-checkpoint+jws', crit: ['x'] }), 't').problems, 'does not use');
  has(readToken(signToken(key, { ...payload, kid: 'psn-dev-2026-1' }), 't').problems, "kid echo is not the header's kid");
});

test('fence: a dev checkpoint in a prod mirror is refused, and a prod kid in a dev mirror', () => {
  const devWorld = world({ key: makeKey('psn-dev-2026-9') });
  const files = { ...devWorld.files };
  const name = '20261001T000012Z_2';
  files[`checkpoints/${name}.jws`] = Buffer.from(devWorld.jws);
  has(verifyState(stateFromFiles(files), { env: 'prod' }).problems, 'outside the prod fence');

  const prodWorld = world({ key: makeKey('psn-prod-2026-9') });
  const pfiles = { ...prodWorld.files, [`checkpoints/${name}.jws`]: Buffer.from(prodWorld.jws) };
  const result = verifyState(stateFromFiles(pfiles), { env: 'dev' });
  has(result.problems, 'outside the dev fence');
});

test('fence: the matching environment passes', () => {
  const w = world({ key: makeKey('psn-prod-2026-9') });
  const files = { ...w.files, 'checkpoints/20261001T000012Z_2.jws': Buffer.from(w.jws) };
  assert.deepEqual(verifyState(stateFromFiles(files), { env: 'prod' }).problems, []);
});
