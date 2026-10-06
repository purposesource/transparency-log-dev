// One state of the mirror, checked as a whole. Used three ways:
//   - tools/verify.mjs, by anyone, on a checkout;
//   - tools/mirror.mjs, on the mirror as it stands (it must be clean before anything is added)
//     and on the state the served bytes would make (whatever that adds is an incident);
//   - tools/verify.mjs --history, on every commit in turn.
//
// A PROBLEM is something the bytes contradict: a schema break, a broken chain, a bad
// signature, a checkpoint that commits to another log. A PENDING note is something the
// mirror cannot check YET because a copy is still short (the edge caches a numbered segment
// for up to a day, plan correction 3); it is checked again on every run.

import {
  CHECKPOINT_HEADER_MEMBERS,
  CHECKPOINT_MEMBERS,
  CHECKPOINT_TYP,
  ENTRIES_PER_SEGMENT,
  ENTRY_KINDS,
  ENTRY_MEMBERS,
  ENVIRONMENTS,
  KID_PATTERN,
} from './spec.mjs';
import {
  checkpointArtifactProblems,
  checkpointPayloadProblems,
  instantMs,
  isObject,
  jwksProblems,
  parseJson,
  piiProblems,
  segmentProblems,
  swhRecordProblems,
} from './schema.mjs';
import { published, renderCheckpointArtifact, renderCut, renderLatest, renderSegment, sha256Hex } from './canonical.mjs';
import { parseCompact, verifyEs256 } from './jws.mjs';
import { safePath } from './state.mjs';

const byName = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
const short = (hex) => (typeof hex === 'string' ? `${hex.slice(0, 12)}…` : 'none');

/** checkpoints/{stamp}_{headSeq}: the signed asOf without colons (Windows refuses them in a path, plan correction 1). */
export function checkpointName(asOf, headSeq) {
  const ms = instantMs(asOf);
  if (ms === null || !Number.isSafeInteger(headSeq)) return null;
  const iso = new Date(ms).toISOString(); // 2026-10-01T00:20:21.000Z
  const millis = iso.slice(20, 23);
  return `${iso.slice(0, 19).replaceAll('-', '').replaceAll(':', '')}${millis === '000' ? '' : `.${millis}`}Z_${headSeq}`;
}

/** A UTC instant as a colon-free stamp, YYYYMMDDTHHMMSSZ (incident folder names). */
export function stamp(date) {
  return date.toISOString().slice(0, 19).replaceAll('-', '').replaceAll(':', '') + 'Z';
}

const COMPACT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * One checkpoint token: its header and payload against the profile and ct-checkpoint.v1, and
 * the no-names rule over both. Returns { header, payload, signature, signingInput, problems }.
 */
export function readToken(text, at) {
  if (typeof text !== 'string' || !COMPACT.test(text)) return { problems: [`${at} is not exactly one compact JWS`] };
  const parsed = parseCompact(text);
  if (parsed.problem) return { problems: [`${at}: ${parsed.problem}`] };
  const { header, payload } = parsed;
  const problems = [];
  if (!isObject(header)) problems.push(`${at}: the protected header is not an object`);
  else {
    for (const k of Object.keys(header)) if (!CHECKPOINT_HEADER_MEMBERS.includes(k)) problems.push(`${at}: the protected header carries a member the checkpoint profile does not use`);
    if (header.alg !== 'ES256') problems.push(`${at}: the protected header's alg is not ES256`);
    if (header.typ !== CHECKPOINT_TYP) problems.push(`${at}: the protected header's typ is not ${CHECKPOINT_TYP}`);
    if (!(typeof header.kid === 'string' && KID_PATTERN.test(header.kid))) problems.push(`${at}: the protected header's kid does not match the kid pattern`);
  }
  problems.push(...checkpointPayloadProblems(payload, `${at} payload`));
  problems.push(...piiProblems(header, `${at} header`), ...piiProblems(payload, `${at} payload`));
  if (problems.length === 0 && Object.hasOwn(payload, 'kid') && payload.kid !== header.kid) problems.push(`${at}: the payload's kid echo is not the header's kid`);
  return { ...parsed, problems };
}

/**
 * One served or mirrored file: parsed, held to its contract, held to the no-names rule, and
 * held to the byte form the platform publishes. `kind` is numbered | latest |
 * checkpoint-artifact | jwks | swh-record.
 */
export function readFile(bytes, file, kind, { env, name } = {}) {
  const out = { doc: null, schema: [], pii: [], form: [] };
  const parsed = parseJson(bytes);
  if (parsed.problem) {
    out.schema.push(`${file} ${parsed.problem}`);
    return out;
  }
  const doc = parsed.value;
  out.pii = piiProblems(doc, file);
  if (kind === 'numbered' || kind === 'latest') out.schema = segmentProblems(doc, file, kind);
  else if (kind === 'checkpoint-artifact') {
    out.schema = checkpointArtifactProblems(doc, file);
    if (out.schema.length === 0) {
      const token = readToken(doc.jws, `${file} jws`);
      out.schema.push(...token.problems);
      if (token.problems.length === 0 && !samePayload(doc.payload, token.payload)) {
        out.schema.push(`${file}: the convenience payload says something the signed payload does not`);
      }
      out.token = token;
    }
  } else if (kind === 'jwks') out.schema = jwksProblems(doc, file, env);
  else if (kind === 'swh-record') out.schema = swhRecordProblems(doc, file, name);
  if (out.schema.length === 0) {
    out.doc = doc;
    let expected = null;
    if (kind === 'numbered') expected = renderSegment(doc);
    else if (kind === 'latest') expected = renderLatest(doc);
    else if (kind === 'checkpoint-artifact') expected = renderCheckpointArtifact(doc, CHECKPOINT_MEMBERS);
    else if (kind === 'swh-record') expected = published(doc);
    if (expected && !expected.equals(bytes)) out.form.push(`${file} is not in the published byte form (two-space indentation, LF, one trailing newline, the platform's member order)`);
  }
  return out;
}

function samePayload(a, b) {
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && a[k] === b[k]);
}

function sameEntry(a, b) {
  return ENTRY_MEMBERS.every((m) => a[m] === b[m]);
}

/** Why two copies of one segment are not one log (the shorter must be a prefix of the longer), or null. */
function disagreement(a, b) {
  const [s, l] = a.doc.entries.length <= b.doc.entries.length ? [a, b] : [b, a];
  for (const m of ['segment', 'startSeq', 'prevSegmentSha256']) {
    if (s.doc[m] !== l.doc[m]) return `${s.label} and ${l.label} disagree about \`${m}\` of segment ${l.doc.segment}`;
  }
  for (let i = 0; i < s.doc.entries.length; i++) {
    if (!sameEntry(s.doc.entries[i], l.doc.entries[i])) {
      return `${s.label} and ${l.label} disagree at seq ${l.doc.entries[i].seq}: one is not a prefix of the other, so an entry was rewritten or removed`;
    }
  }
  return null;
}

/**
 * Checks one state. `extra` are further copies of segments to hold against it (the mirrored
 * copies a run is about to replace, and served copies it is not adopting).
 * Returns { problems, pending, notes, view }.
 */
export function verifyState(state, { env, extra = [] } = {}) {
  const problems = [];
  const pending = [];
  const notes = [];

  for (const path of state.strays) problems.push(`${safePath(path)} does not belong in the mirror's layout`);

  // 1. Every file on its own.
  const accept = (r) => {
    problems.push(...r.schema, ...r.pii, ...r.form);
    return r.schema.length === 0 && r.pii.length === 0 && r.form.length === 0 ? r.doc : null;
  };
  const versions = new Map(); // segment → [{label, doc}]
  const addVersion = (label, doc) => {
    if (!versions.has(doc.segment)) versions.set(doc.segment, []);
    versions.get(doc.segment).push({ label, doc });
  };
  for (const [n, bytes] of [...state.segments].sort((a, b) => a[0] - b[0])) {
    const doc = accept(readFile(bytes, `ct/${n}.json`, 'numbered'));
    if (!doc) continue;
    if (doc.segment !== n) problems.push(`ct/${n}.json declares segment ${doc.segment}`);
    else addVersion(`ct/${n}.json`, doc);
  }
  const latestDoc = state.latest ? accept(readFile(state.latest, 'ct/latest.json', 'latest')) : null;
  if (latestDoc) addVersion('ct/latest.json', latestDoc);
  for (const v of extra) addVersion(v.label, v.doc);
  const keyDoc = state.jwks ? accept(readFile(state.jwks, 'jwks.json', 'jwks', { env })) : null;
  let ckpLatest = null;
  if (state.checkpointLatest) {
    const r = readFile(state.checkpointLatest, 'ct/checkpoint-latest.json', 'checkpoint-artifact');
    if (accept(r)) ckpLatest = { doc: r.doc, token: r.token };
  }

  // 2. Copies of one segment must be one log: the shorter a prefix of the longer.
  const best = new Map();
  for (const [n, list] of versions) {
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const why = disagreement(list[i], list[j]);
        if (why) problems.push(why);
      }
    }
    best.set(n, list.reduce((a, b) => (b.doc.entries.length > a.doc.entries.length ? b : a)));
  }

  // 3. The whole log: segments chained, seq contiguous, the entry rules across segments.
  const maxSegment = best.size ? Math.max(...best.keys()) : -1;
  const hashes = new Map();
  let lastTs = null;
  let gap = false;
  let headSeq = -1;
  for (let n = 0; n <= maxSegment; n++) {
    const seg = best.get(n);
    if (!seg) {
      pending.push(`segment ${n} is not mirrored yet, although a later segment is; its link is checked once it is`);
      gap = true;
      continue;
    }
    const prev = best.get(n - 1);
    if (n > 0 && prev && prev.doc.entries.length === ENTRIES_PER_SEGMENT) {
      const link = sha256Hex(renderSegment(prev.doc));
      if (seg.doc.prevSegmentSha256 !== link) {
        problems.push(`segment ${n} names prevSegmentSha256 ${short(seg.doc.prevSegmentSha256)} and closed segment ${n - 1} hashes to ${short(link)}: the chain does not recompute`);
      }
    } else if (n > 0 && prev) {
      pending.push(`segment ${n - 1} holds ${prev.doc.entries.length} entries in the mirror's newest copy and is no longer the open segment; its closed copy is not served yet (a numbered segment is cached for up to a day), so the link to segment ${n} waits`);
    }
    for (const e of seg.doc.entries) {
      const ts = instantMs(e.ts);
      if (lastTs !== null && ts < lastTs) problems.push(`seq ${e.seq}: \`ts\` is earlier than the entry before it; the log is time-ordered`);
      lastTs = ts;
      if (hashes.has(e.h)) problems.push(`seq ${e.seq}: \`h\` ${short(e.h)} is already logged at seq ${hashes.get(e.h)}`);
      const kind = ENTRY_KINDS[e.kind];
      if (kind?.refersTo === 'earlier' && e.ref !== null && !hashes.has(e.ref)) {
        if (gap) pending.push(`seq ${e.seq}: \`ref\` ${short(e.ref)} is not in the mirrored part of the log yet`);
        else problems.push(`seq ${e.seq}: \`ref\` ${short(e.ref)} names no earlier entry in this log`);
      }
      if (!hashes.has(e.h)) hashes.set(e.h, e.seq);
      headSeq = e.seq;
    }
    if (n < maxSegment && seg.doc.entries.length < ENTRIES_PER_SEGMENT) gap = true;
  }

  // 4. Checkpoints: each a valid token under a mirrored key, inside the fence, committing to this log.
  const keys = new Map((keyDoc?.keys ?? []).map((k) => [k.kid, k]));
  const fence = ENVIRONMENTS[env]?.kidPrefix;
  const checkpoints = [];
  for (const [name, bytes] of [...state.checkpoints].sort(byName)) {
    const at = `checkpoints/${name}.jws`;
    const token = readToken(bytes.toString('latin1'), at);
    if (token.problems.length) {
      problems.push(...token.problems);
      continue;
    }
    const { header, payload } = token;
    if (checkpointName(payload.asOf, payload.headSeq) !== name) problems.push(`${at}: its name does not follow from its signed asOf and headSeq`);
    if (fence && !header.kid.startsWith(fence)) problems.push(`${at}: signed under ${header.kid}, outside the ${env} fence (${fence}…)`);
    const key = keys.get(header.kid);
    if (!key) problems.push(`${at}: signed under ${header.kid}, which the mirrored key set does not carry`);
    else if (!verifyEs256(token.signingInput, token.signature, key)) problems.push(`${at}: the signature does not verify under ${header.kid}`);
    else notes.push(...keyWindowNotes(at, key, payload.asOf));

    const seg = best.get(payload.headSegment);
    const need = payload.headSeq - payload.headSegment * ENTRIES_PER_SEGMENT + 1;
    if (!seg || seg.doc.entries.length < need) {
      pending.push(`${at}: the mirror's copy of segment ${payload.headSegment} does not reach seq ${payload.headSeq} yet, so headSegmentSha256 waits`);
    } else {
      const got = sha256Hex(renderCut(seg.doc, payload.headSeq));
      if (got !== payload.headSegmentSha256) {
        problems.push(`${at}: headSegmentSha256 ${short(payload.headSegmentSha256)} is not the SHA-256 of segment ${payload.headSegment} cut at seq ${payload.headSeq} and re-rendered (${short(got)}): the checkpoint commits to a different log`);
      }
      const head = seg.doc.entries[need - 1];
      if (instantMs(head.ts) > instantMs(payload.asOf)) problems.push(`${at}: the entry at headSeq ${payload.headSeq} is later than asOf, so it cannot be the head at asOf`);
    }
    checkpoints.push({ name, asOf: payload.asOf, ms: instantMs(payload.asOf), headSeq: payload.headSeq, kid: header.kid, jws: bytes.toString('latin1') });
  }
  checkpoints.sort((a, b) => a.ms - b.ms);
  for (let i = 1; i < checkpoints.length; i++) {
    const [a, b] = [checkpoints[i - 1], checkpoints[i]];
    if (a.ms === b.ms) problems.push(`checkpoints/${a.name}.jws and checkpoints/${b.name}.jws commit at the same asOf`);
    else if (b.headSeq < a.headSeq) problems.push(`checkpoints/${b.name}.jws is later than checkpoints/${a.name}.jws and commits to an earlier head (${b.headSeq} < ${a.headSeq})`);
  }
  if (ckpLatest) {
    const held = checkpoints.find((c) => c.jws === ckpLatest.doc.jws);
    if (!held) problems.push('ct/checkpoint-latest.json holds a token that is not kept under checkpoints/');
    else if (checkpoints.length && held !== checkpoints[checkpoints.length - 1]) problems.push('ct/checkpoint-latest.json is not the newest checkpoint the mirror holds');
  } else if (checkpoints.length && !state.checkpointLatest) {
    problems.push('checkpoints/ holds checkpoints and ct/checkpoint-latest.json is missing');
  }

  // 5. The Software Heritage records beside the checkpoints.
  for (const [name, bytes] of [...state.swhRecords].sort(byName)) {
    const file = `checkpoints/${name}.swh.json`;
    if (!state.checkpoints.has(name)) problems.push(`${file} has no checkpoint beside it`);
    const r = readFile(bytes, file, 'swh-record', { name });
    problems.push(...r.schema, ...r.pii, ...r.form);
  }

  const latestSeg = latestDoc?.segment ?? maxSegment;
  return {
    problems: [...new Set(problems)],
    pending: [...new Set(pending)],
    notes: [...new Set(notes)],
    view: { best, maxSegment, headSeq, latestDoc, latestSegment: latestSeg, keyDoc, checkpoints, ckpLatest },
  };
}

/** Whether the key's published window and status allowed it to sign at asOf (key-window rule; a note, never a problem). */
function keyWindowNotes(at, key, asOf) {
  const w = key['psn:validityWindow'];
  const t = instantMs(asOf);
  const out = [];
  if (w && instantMs(w.notBefore) !== null && t < instantMs(w.notBefore)) out.push(`${at}: asOf is before ${key.kid}'s window opens`);
  if (w && w.notAfter && t >= instantMs(w.notAfter)) out.push(`${at}: asOf is at or after ${key.kid}'s window closed`);
  if (key['psn:status'] === 'compromised') out.push(`${at}: ${key.kid} is published as compromised`);
  return out;
}
