// Test helpers: the live dev fixtures, a synthetic log rendered the way the platform renders
// it, an ephemeral P-256 key made fresh for each test run (no key is stored anywhere), temp git
// repositories, and fake HTTP answers.

import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { jcs, ownEntryHash, published, renderLatest, renderSegment, sha256Hex } from '../tools/lib/canonical.mjs';
import { CHECKPOINT_MEMBERS, ENTRIES_PER_SEGMENT } from '../tools/lib/spec.mjs';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const FIXTURES = join(HERE, 'fixtures', 'dev-2026-10-06');
export const ORIGIN = 'https://dev-api.purposesource.org';

/** The live dev bytes fetched on 2026-10-06, by layout path. */
export function devFixtures() {
  const read = (p) => readFileSync(join(FIXTURES, p));
  return {
    'ct/latest.json': read('ct/latest.json'),
    'ct/0.json': read('ct/0.json'),
    'ct/checkpoint-latest.json': read('ct/checkpoint-latest.json'),
    'jwks.json': read('jwks.json'),
  };
}

/** A served set (what the edge answered) from layout paths to bytes; a path set to a number answers that status. */
export function servedFrom(files, fetchedAt = '2026-10-06T09:16:06Z') {
  const r = (v) => (v === undefined ? { status: 404 } : typeof v === 'number' ? { status: v } : { status: 200, bytes: Buffer.from(v) });
  const segments = new Map();
  for (const [path, v] of Object.entries(files)) {
    const m = /^ct\/(\d+)\.json$/.exec(path);
    if (m) segments.set(Number(m[1]), r(v));
  }
  return { latest: r(files['ct/latest.json']), segments, checkpointLatest: r(files['ct/checkpoint-latest.json']), jwks: r(files['jwks.json']), fetchedAt };
}

const HOUR = 3_600_000;

/**
 * A clock for lib/evaluate.mjs: `now` and the mirror's commit dates, all as ISO strings.
 * `committed` maps a layout path to its commit date; `held` maps a segment to the date from
 * which the mirror has held it as its open segment. A path not named counts as uncommitted.
 */
export function fakeClock({ now = '2026-10-06T12:00:00Z', committed = {}, held = {} } = {}) {
  const ms = (v) => (v === undefined ? null : Date.parse(v));
  return { now: Date.parse(now), committedAt: (path) => ms(committed[path]), heldSince: (segment) => ms(held[segment]) };
}

/** An ISO instant `h` hours before `iso`. */
export const hoursBefore = (iso, h) => new Date(Date.parse(iso) - h * HOUR).toISOString().slice(0, 19) + 'Z';

/* ------------------------------------------------------------------ a synthetic log */

const BASE_TS = Date.UTC(2026, 9, 1, 0, 0, 0);
export const tsAt = (i) => new Date(BASE_TS + i * 1000).toISOString().slice(0, 19) + 'Z';

/** `count` issue entries (seq 0…count-1), one second apart. */
export function issueEntries(count, from = 0) {
  return Array.from({ length: count }, (_, k) => {
    const i = from + k;
    return { seq: i, h: sha256Hex(`entry-${i}`), typ: 'supporter', kind: 'issue', ref: null, ts: tsAt(i) };
  });
}

/** A revoke (or status/record) entry at `seq` naming `ref`, with its own h computed as the contract defines. */
export function ownHashEntry(seq, ref, kind = 'revoke', typ = 'supporter') {
  const e = { seq, h: '', typ, kind, ref, ts: tsAt(seq) };
  e.h = ownEntryHash(e);
  return e;
}

/**
 * The platform's files for a log holding `entries`: ct/{n}.json for every segment, the chain
 * computed over the published bytes, and ct/latest.json for the open one.
 */
export function renderLog(entries, generatedAt = '2026-10-06T00:00:00Z') {
  const files = {};
  const last = entries.length ? Math.floor(entries[entries.length - 1].seq / ENTRIES_PER_SEGMENT) : 0;
  let prev = null;
  let open = null;
  for (let n = 0; n <= last; n++) {
    const doc = {
      schemaVersion: 1,
      segment: n,
      startSeq: n * ENTRIES_PER_SEGMENT,
      prevSegmentSha256: prev,
      entries: entries.filter((e) => Math.floor(e.seq / ENTRIES_PER_SEGMENT) === n),
    };
    const bytes = renderSegment(doc);
    files[`ct/${n}.json`] = bytes;
    prev = sha256Hex(bytes);
    open = doc;
  }
  files['ct/latest.json'] = renderLatest({ ...open, generatedAt, closed: open.entries.length >= ENTRIES_PER_SEGMENT });
  return files;
}

/* ------------------------------------------------------------------- keys, tokens */

/** A fresh P-256 key under `kid`, its published key-set entry, and a signer. */
export function makeKey(kid = 'psn-dev-2026-9', notBefore = '2026-09-01T00:00:00Z') {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' });
  const entry = {
    kty: 'EC',
    crv: 'P-256',
    x: pub.x,
    y: pub.y,
    kid,
    alg: 'ES256',
    use: 'sig',
    'psn:status': 'active',
    'psn:validityWindow': { notBefore, notAfter: null },
  };
  return { kid, entry, privateKey };
}

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64url');

/** A compact checkpoint JWS: JCS header {alg, kid, typ}, JCS payload, raw r||s signature. */
export function signToken(key, payload, header = { alg: 'ES256', kid: key.kid, typ: 'application/psn-ct-checkpoint+jws' }) {
  const input = `${b64(jcs(header))}.${b64(jcs(payload))}`;
  const sig = sign('sha256', Buffer.from(input, 'ascii'), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

/** The payload a checkpoint over `files` at headSeq would carry (headSegmentSha256 from the platform's cut). */
export function checkpointPayload(key, entries, headSeq, asOf, iss = ORIGIN) {
  const seg = Math.floor(headSeq / ENTRIES_PER_SEGMENT);
  const doc = {
    schemaVersion: 1,
    segment: seg,
    startSeq: seg * ENTRIES_PER_SEGMENT,
    prevSegmentSha256: seg === 0 ? null : sha256Hex(renderLog(entries.filter((e) => e.seq < seg * ENTRIES_PER_SEGMENT))[`ct/${seg - 1}.json`]),
    entries: entries.filter((e) => e.seq <= headSeq && Math.floor(e.seq / ENTRIES_PER_SEGMENT) === seg),
  };
  return { asOf, headSeq, headSegment: seg, headSegmentSha256: sha256Hex(renderSegment(doc)), kid: key.kid, iss };
}

/** /ct/checkpoint-latest.json for a token, published as the platform publishes it. */
export function checkpointArtifact(jws, payload, generatedAt = '2026-10-06T00:00:00Z') {
  const ordered = {};
  for (const m of CHECKPOINT_MEMBERS) if (Object.hasOwn(payload, m)) ordered[m] = payload[m];
  return published({ schemaVersion: 1, generatedAt, jws, payload: ordered });
}

/** /jwks.json for key-set entries. */
export function jwksFile(entries, generatedAt = '2026-10-06T00:00:00Z') {
  return published({ schemaVersion: 1, generatedAt, keys: entries });
}

/** A complete, consistent set of served files: the log, a checkpoint at headSeq, and the key set. */
export function world({ count = 3, headSeq = count - 1, asOf = tsAt(headSeq + 10), key = makeKey(), generatedAt } = {}) {
  const entries = issueEntries(count);
  const files = renderLog(entries, generatedAt);
  const payload = checkpointPayload(key, entries, headSeq, asOf);
  const jws = signToken(key, payload);
  files['ct/checkpoint-latest.json'] = checkpointArtifact(jws, payload, generatedAt);
  files['jwks.json'] = jwksFile([key.entry], generatedAt);
  return { files, entries, key, payload, jws };
}

/* --------------------------------------------------------------- git and HTTP fakes */

/** A fresh git repository in the temp directory. */
export function tempRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'ctmirror-'));
  const g = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  g('init', '-q', '-b', 'main');
  g('config', 'user.name', 'Test');
  g('config', 'user.email', 'test@example.invalid');
  g('config', 'core.autocrlf', 'false');
  g('commit', '-q', '--allow-empty', '-m', 'empty');
  return { dir, git: g };
}

/** A fetch that answers from `files` (layout paths under ORIGIN); anything else is 404. Records every URL asked. */
export function edgeFetch(files, { origin = ORIGIN, statuses = {} } = {}) {
  const asked = [];
  const fn = async (url) => {
    asked.push(url);
    const path = url.slice(origin.length + 1);
    if (Object.hasOwn(statuses, path)) return new Response('{"error":{}}', { status: statuses[path] });
    if (!Object.hasOwn(files, path)) return new Response('{"error":{"code":"artifact_not_found"}}', { status: 404 });
    return new Response(files[path], { status: 200 });
  };
  fn.asked = asked;
  return fn;
}

export const silent = () => {};
