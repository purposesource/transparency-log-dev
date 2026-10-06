// The contracts, written as code: ct-segment.v1, ct-checkpoint.v1, and the Jwks and
// CtCheckpointArtifact components of edge-public.v1. Plus the no-names rule (plan
// correction 8): nothing email-shaped or name-shaped may enter this repository, because
// Software Heritage keeps everything for ever and cannot honour an erasure request.
//
// MESSAGES NEVER QUOTE A SERVED VALUE. A problem names the path and the rule; a value is
// quoted only after it matched a pattern that cannot carry a name (a hash, a kid, an
// integer). Problem texts go into commit messages, incident files and public issues.

import { createPublicKey } from 'node:crypto';

import {
  CHECKPOINT_ARTIFACT_MEMBERS,
  CHECKPOINT_MEMBERS,
  CHECKPOINT_REQUIRED,
  ENTRIES_PER_SEGMENT,
  ENTRY_KINDS,
  ENTRY_MEMBERS,
  ENTRY_TYPS,
  ENVIRONMENTS,
  JWKS_ALLOWED,
  KEY_MATERIAL,
  KEY_STANDING,
  KEY_STATUSES,
  KID_PATTERN,
  MAX_SEGMENT,
  SEGMENT_ALLOWED,
  SHA256_HEX,
  SOURCES,
} from './spec.mjs';
import { ownEntryHash } from './canonical.mjs';

/* ------------------------------------------------------------------ parsing */

/**
 * Bytes to a JSON value, refusing what a second reader could read differently: invalid
 * UTF-8, a byte-order mark, and an object naming a member twice (JSON.parse keeps the last
 * one silently; another parser may keep the first).
 */
export function parseJson(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { problem: 'is not valid UTF-8' };
  }
  if (text.charCodeAt(0) === 0xfeff) return { problem: 'starts with a byte-order mark' };
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { problem: 'is not JSON' };
  }
  if (hasDuplicateMember(text)) return { problem: 'names a member twice in one object' };
  return { value };
}

/** True when some object in the (already valid) JSON text names a member twice. */
export function hasDuplicateMember(text) {
  const stack = []; // each frame: a Set for an object, null for an array
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      let raw = '';
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\') {
          raw += text.slice(j, j + 2);
          j += 2;
        } else {
          raw += text[j];
          j += 1;
        }
      }
      const frame = stack[stack.length - 1];
      if (expectKey && frame instanceof Set) {
        const key = JSON.parse(`"${raw}"`);
        if (frame.has(key)) return true;
        frame.add(key);
      }
      expectKey = false;
      i = j;
    } else if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
      expectKey = false;
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
  }
  return false;
}

/* --------------------------------------------------------------- primitives */

export const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const isUint = (v) => Number.isSafeInteger(v) && v >= 0;
export const isSha256 = (v) => typeof v === 'string' && SHA256_HEX.test(v);

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?([Zz]|([+-])(\d{2}):(\d{2}))$/;

/** Milliseconds since the epoch for an RFC 3339 date-time, or null when it is not one. Leap seconds are refused. */
export function instantMs(value) {
  if (typeof value !== 'string') return null;
  const m = RFC3339.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59) return null;
  const days = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (d < 1 || d > days) return null;
  let offset = 0;
  if (m[9]) {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offset = (oh * 60 + om) * 60000 * (m[9] === '-' ? -1 : 1);
  }
  const ms = m[7] ? Number(m[7].slice(1, 4).padEnd(3, '0')) : 0;
  return Date.UTC(y, mo - 1, d, h, mi, s, ms) - offset;
}

export const isDateTime = (v) => instantMs(v) !== null;

/**
 * A member name is quoted only when the contracts define it. An unknown member's name is
 * never repeated: it is served content, and `JohnSmith` is as much a name as `John Smith`.
 */
const KNOWN_MEMBERS = new Set([
  ...SEGMENT_ALLOWED,
  ...ENTRY_MEMBERS,
  ...CHECKPOINT_MEMBERS,
  ...CHECKPOINT_ARTIFACT_MEMBERS,
  ...JWKS_ALLOWED,
  ...KEY_MATERIAL,
  ...KEY_STANDING,
  'notBefore',
  'notAfter',
]);
function memberLabel(name) {
  return KNOWN_MEMBERS.has(name) ? `\`${name}\`` : 'a member';
}

/* ------------------------------------------------------------ the no-names rule */

/** Something an email address would match. */
export const EMAIL_SHAPED = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

/**
 * Every string (member names included) that is email-shaped, or name-shaped: holding
 * whitespace or an `@`. Nothing the log, its checkpoints or its key set legitimately carry
 * has either; a person's name nearly always has a space.
 */
export function piiProblems(value, path = '') {
  const out = [];
  const visit = (v, p) => {
    if (typeof v === 'string') {
      if (EMAIL_SHAPED.test(v)) out.push(`${p || 'the document'} holds an email-shaped value`);
      else if (/[\s@]/.test(v)) out.push(`${p || 'the document'} holds a name-shaped value (whitespace or @)`);
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => visit(item, `${p}[${i}]`));
    } else if (isObject(v)) {
      for (const [k, item] of Object.entries(v)) {
        if (EMAIL_SHAPED.test(k) || /[\s@]/.test(k)) out.push(`${p || 'the document'} names a member that is email- or name-shaped`);
        visit(item, p ? `${p}.${memberLabel(k).replaceAll('`', '')}` : memberLabel(k).replaceAll('`', ''));
      }
    }
  };
  visit(value, path);
  return out;
}

/* --------------------------------------------------------------- ct-segment.v1 */

/** The rules one entry obeys on its own (`at` names it in messages). */
export function entryProblems(entry, at) {
  const out = [];
  if (!isObject(entry)) return [`${at} is not an object`];
  for (const k of Object.keys(entry)) {
    if (!ENTRY_MEMBERS.includes(k)) out.push(`${at} carries ${memberLabel(k)}, which ct-segment.v1 does not define (entries carry nothing else)`);
  }
  for (const k of ENTRY_MEMBERS) if (!Object.hasOwn(entry, k)) out.push(`${at} has no \`${k}\``);
  if (Object.hasOwn(entry, 'seq') && !isUint(entry.seq)) out.push(`${at}: \`seq\` is not an integer from 0`);
  if (Object.hasOwn(entry, 'h') && !isSha256(entry.h)) out.push(`${at}: \`h\` is not 64 lowercase hex characters`);
  if (Object.hasOwn(entry, 'typ') && !ENTRY_TYPS.includes(entry.typ)) out.push(`${at}: \`typ\` is not one ct-segment.v1 defines`);
  const kind = Object.hasOwn(ENTRY_KINDS, entry.kind) ? ENTRY_KINDS[entry.kind] : null;
  if (Object.hasOwn(entry, 'kind') && !kind) out.push(`${at}: \`kind\` is not one this verifier knows (issue, revoke, status, record)`);
  if (Object.hasOwn(entry, 'ref') && entry.ref !== null && !isSha256(entry.ref)) out.push(`${at}: \`ref\` is neither null nor 64 lowercase hex characters`);
  if (Object.hasOwn(entry, 'ts') && !isDateTime(entry.ts)) out.push(`${at}: \`ts\` is not an RFC 3339 date-time`);
  if (out.length === 0 && kind) {
    if (kind.refersTo === null && entry.ref !== null) out.push(`${at}: an \`${entry.kind}\` entry references nothing, so \`ref\` must be null`);
    if (kind.refersTo === 'earlier' && entry.ref === null) out.push(`${at}: a \`${entry.kind}\` entry must name the original entry's hash in \`ref\` (CERT-033)`);
    if (kind.ownHash && entry.ref !== null) {
      if (entry.h === entry.ref) out.push(`${at}: \`h\` equals \`ref\`; a \`${entry.kind}\` entry is a new object, not a second pointer`);
      else if (entry.h !== ownEntryHash(entry)) out.push(`${at}: \`h\` is not the SHA-256 of the entry's own members {kind, ref, ts, typ} in RFC 8785 form`);
    }
  }
  return out;
}

/**
 * ct-segment.v1 for one document, plus the structure FS08-111 gives a segment (startSeq is
 * segment × 10000, entries run on from it with no gap, only segment 0 has no predecessor).
 * `role` is 'numbered' for /ct/{n}.json and 'latest' for /ct/latest.json.
 */
export function segmentProblems(doc, file, role) {
  const out = [];
  if (!isObject(doc)) return [`${file} is not a JSON object`];
  for (const k of Object.keys(doc)) {
    if (!SEGMENT_ALLOWED.includes(k)) out.push(`${file} carries ${memberLabel(k)}, which ct-segment.v1 does not define`);
  }
  for (const k of ['schemaVersion', 'segment', 'startSeq', 'prevSegmentSha256', 'entries']) {
    if (!Object.hasOwn(doc, k)) out.push(`${file} has no \`${k}\``);
  }
  if (Object.hasOwn(doc, 'schemaVersion') && doc.schemaVersion !== 1) out.push(`${file}: \`schemaVersion\` is not 1`);
  if (Object.hasOwn(doc, 'segment') && !(isUint(doc.segment) && doc.segment <= MAX_SEGMENT)) out.push(`${file}: \`segment\` is not an integer from 0 to ${MAX_SEGMENT}`);
  if (Object.hasOwn(doc, 'startSeq') && !isUint(doc.startSeq)) out.push(`${file}: \`startSeq\` is not an integer from 0`);
  if (Object.hasOwn(doc, 'prevSegmentSha256') && doc.prevSegmentSha256 !== null && !isSha256(doc.prevSegmentSha256)) {
    out.push(`${file}: \`prevSegmentSha256\` is neither null nor 64 lowercase hex characters`);
  }
  if (Object.hasOwn(doc, 'generatedAt') && !isDateTime(doc.generatedAt)) out.push(`${file}: \`generatedAt\` is not an RFC 3339 date-time`);
  if (Object.hasOwn(doc, 'source') && !SOURCES.includes(doc.source)) out.push(`${file}: \`source\` is not one ct-segment.v1 defines`);
  if (Object.hasOwn(doc, 'closed') && typeof doc.closed !== 'boolean') out.push(`${file}: \`closed\` is not a boolean`);
  if (Object.hasOwn(doc, 'entries')) {
    if (!Array.isArray(doc.entries)) out.push(`${file}: \`entries\` is not an array`);
    else {
      if (doc.entries.length > ENTRIES_PER_SEGMENT) out.push(`${file} holds ${doc.entries.length} entries, more than the ${ENTRIES_PER_SEGMENT} a segment holds`);
      doc.entries.forEach((e, i) => out.push(...entryProblems(e, `${file} entries[${i}]`)));
    }
  }
  if (out.length > 0) return out;

  // FS08-111's structure, which the contract states in its descriptions.
  if (doc.startSeq !== doc.segment * ENTRIES_PER_SEGMENT) out.push(`${file}: \`startSeq\` is not segment × ${ENTRIES_PER_SEGMENT}`);
  if (doc.segment === 0 && doc.prevSegmentSha256 !== null) out.push(`${file}: segment 0 has no predecessor, so \`prevSegmentSha256\` must be null`);
  if (doc.segment > 0 && doc.prevSegmentSha256 === null) out.push(`${file}: segment ${doc.segment} must name its predecessor's hash in \`prevSegmentSha256\``);
  doc.entries.forEach((e, i) => {
    if (e.seq !== doc.startSeq + i) out.push(`${file} entries[${i}]: \`seq\` is ${e.seq}, and entries run on from startSeq with no gap (expected ${doc.startSeq + i})`);
  });
  if (role === 'latest') {
    if (!Object.hasOwn(doc, 'generatedAt')) out.push(`${file}: the open segment carries \`generatedAt\``);
    if (!Object.hasOwn(doc, 'closed')) out.push(`${file}: the open segment declares \`closed\``);
    else if (doc.closed !== (doc.entries.length >= ENTRIES_PER_SEGMENT)) out.push(`${file}: \`closed\` does not follow from the entry count`);
  }
  return out;
}

/* ------------------------------------------------------------ ct-checkpoint.v1 */

/** The issuer, stricter than `format: uri`: an https origin with an optional path, so no user-info can carry a name. */
const ISSUER = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;

/** ct-checkpoint.v1 for a decoded payload. */
export function checkpointPayloadProblems(p, at) {
  const out = [];
  if (!isObject(p)) return [`${at} is not a JSON object`];
  for (const k of Object.keys(p)) if (!CHECKPOINT_MEMBERS.includes(k)) out.push(`${at} carries ${memberLabel(k)}, which ct-checkpoint.v1 does not define`);
  for (const k of CHECKPOINT_REQUIRED) if (!Object.hasOwn(p, k)) out.push(`${at} has no \`${k}\``);
  if (Object.hasOwn(p, 'asOf') && !isDateTime(p.asOf)) out.push(`${at}: \`asOf\` is not an RFC 3339 date-time`);
  if (Object.hasOwn(p, 'headSeq') && !isUint(p.headSeq)) out.push(`${at}: \`headSeq\` is not an integer from 0`);
  if (Object.hasOwn(p, 'headSegment') && !isUint(p.headSegment)) out.push(`${at}: \`headSegment\` is not an integer from 0`);
  if (Object.hasOwn(p, 'headSegmentSha256') && !isSha256(p.headSegmentSha256)) out.push(`${at}: \`headSegmentSha256\` is not 64 lowercase hex characters`);
  if (Object.hasOwn(p, 'kid') && !(typeof p.kid === 'string' && KID_PATTERN.test(p.kid))) out.push(`${at}: \`kid\` does not match ct-checkpoint.v1's pattern`);
  if (Object.hasOwn(p, 'iss') && !(typeof p.iss === 'string' && ISSUER.test(p.iss))) out.push(`${at}: \`iss\` is not an https origin`);
  if (out.length === 0 && p.headSegment !== Math.floor(p.headSeq / ENTRIES_PER_SEGMENT)) {
    out.push(`${at}: \`headSegment\` is not the segment \`headSeq\` falls in (headSeq ÷ ${ENTRIES_PER_SEGMENT})`);
  }
  return out;
}

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** edge-public.v1 CtCheckpointArtifact: the envelope only; the payload is checked by checkpointPayloadProblems. */
export function checkpointArtifactProblems(doc, file) {
  const out = [];
  if (!isObject(doc)) return [`${file} is not a JSON object`];
  for (const k of Object.keys(doc)) if (!CHECKPOINT_ARTIFACT_MEMBERS.includes(k)) out.push(`${file} carries ${memberLabel(k)}, which CtCheckpointArtifact does not define`);
  for (const k of CHECKPOINT_ARTIFACT_MEMBERS) if (!Object.hasOwn(doc, k)) out.push(`${file} has no \`${k}\``);
  if (Object.hasOwn(doc, 'schemaVersion') && doc.schemaVersion !== 1) out.push(`${file}: \`schemaVersion\` is not 1`);
  if (Object.hasOwn(doc, 'generatedAt') && !isDateTime(doc.generatedAt)) out.push(`${file}: \`generatedAt\` is not an RFC 3339 date-time`);
  if (Object.hasOwn(doc, 'jws') && !(typeof doc.jws === 'string' && COMPACT_JWS.test(doc.jws))) out.push(`${file}: \`jws\` is not a compact JWS`);
  if (Object.hasOwn(doc, 'payload')) out.push(...checkpointPayloadProblems(doc.payload, `${file} payload`));
  return out;
}

/* ------------------------------------------------------------------------ Jwks */

function base64url32(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === value;
}

/**
 * edge-public.v1 Jwks for /jwks.json, held to what a published set carries: the seven key
 * members and the two `psn:` standing members, nothing else (a member nobody named could be
 * private material); each kid once; each key a point on P-256; `sandbox` absent (it marks
 * only the sandbox set); and every kid inside the environment's fence.
 */
export function jwksProblems(doc, file, env) {
  const out = [];
  if (!isObject(doc)) return [`${file} is not a JSON object`];
  for (const k of Object.keys(doc)) if (!JWKS_ALLOWED.includes(k)) out.push(`${file} carries ${memberLabel(k)}, which the Jwks schema does not define`);
  if (!Array.isArray(doc.keys)) return [...out, `${file}: \`keys\` is not an array`];
  if (Object.hasOwn(doc, 'schemaVersion') && doc.schemaVersion !== 1) out.push(`${file}: \`schemaVersion\` is not 1`);
  if (Object.hasOwn(doc, 'generatedAt') && !isDateTime(doc.generatedAt)) out.push(`${file}: \`generatedAt\` is not an RFC 3339 date-time`);
  if (Object.hasOwn(doc, 'source') && !SOURCES.includes(doc.source)) out.push(`${file}: \`source\` is not one the Jwks schema defines`);
  if (Object.hasOwn(doc, 'sandbox')) out.push(`${file} carries \`sandbox\`, which marks only the sandbox key set`);
  const seen = new Set();
  doc.keys.forEach((key, i) => {
    const at = `${file} keys[${i}]`;
    if (!isObject(key)) {
      out.push(`${at} is not an object`);
      return;
    }
    for (const k of Object.keys(key)) {
      if (!KEY_MATERIAL.includes(k) && !KEY_STANDING.includes(k)) out.push(`${at} carries ${memberLabel(k)}, which a published key does not carry`);
    }
    for (const k of KEY_MATERIAL) if (!Object.hasOwn(key, k)) out.push(`${at} has no \`${k}\``);
    if (Object.hasOwn(key, 'kty') && key.kty !== 'EC') out.push(`${at}: \`kty\` is not EC`);
    if (Object.hasOwn(key, 'crv') && key.crv !== 'P-256') out.push(`${at}: \`crv\` is not P-256`);
    if (Object.hasOwn(key, 'use') && key.use !== 'sig') out.push(`${at}: \`use\` is not sig`);
    if (Object.hasOwn(key, 'alg') && key.alg !== 'ES256') out.push(`${at}: \`alg\` is not ES256`);
    const kidOk = typeof key.kid === 'string' && KID_PATTERN.test(key.kid);
    if (Object.hasOwn(key, 'kid') && !kidOk) out.push(`${at}: \`kid\` does not match the Jwks pattern`);
    if (kidOk) {
      if (seen.has(key.kid)) out.push(`${at}: kid ${key.kid} appears more than once`);
      seen.add(key.kid);
      const prefix = ENVIRONMENTS[env]?.kidPrefix;
      if (prefix && !key.kid.startsWith(prefix)) out.push(`${at}: kid ${key.kid} is outside the ${env} fence (${prefix}…)`);
    }
    const xOk = base64url32(key.x);
    const yOk = base64url32(key.y);
    if (Object.hasOwn(key, 'x') && !xOk) out.push(`${at}: \`x\` is not 32 bytes of unpadded base64url`);
    if (Object.hasOwn(key, 'y') && !yOk) out.push(`${at}: \`y\` is not 32 bytes of unpadded base64url`);
    if (xOk && yOk && key.kty === 'EC' && key.crv === 'P-256') {
      try {
        createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y }, format: 'jwk' });
      } catch {
        out.push(`${at}: (x, y) is not a point on P-256`);
      }
    }
    if (Object.hasOwn(key, 'psn:status') && !KEY_STATUSES.includes(key['psn:status'])) out.push(`${at}: \`psn:status\` is not active, retired or compromised`);
    if (Object.hasOwn(key, 'psn:validityWindow')) {
      const w = key['psn:validityWindow'];
      if (!isObject(w)) out.push(`${at}: \`psn:validityWindow\` is not an object`);
      else {
        for (const k of Object.keys(w)) if (k !== 'notBefore' && k !== 'notAfter') out.push(`${at}: \`psn:validityWindow\` carries ${memberLabel(k)}`);
        if (!isDateTime(w.notBefore)) out.push(`${at}: \`psn:validityWindow.notBefore\` is not an RFC 3339 date-time`);
        if (Object.hasOwn(w, 'notAfter') && w.notAfter !== null && !isDateTime(w.notAfter)) out.push(`${at}: \`psn:validityWindow.notAfter\` is neither null nor an RFC 3339 date-time`);
      }
    }
  });
  return out;
}

/* ---------------------------------------------------- the Software Heritage record */

export const SWH_RECORD_MEMBERS = Object.freeze([
  'checkpoint',
  'origin_url',
  'snapshot_swhid',
  'visit_date',
  'visit_status',
  'save_request_id',
  'save_request_url',
  'mirror_commit',
]);

/** checkpoints/{name}.swh.json, this repository's own record format (README, "Software Heritage"). */
export function swhRecordProblems(doc, file, name) {
  const out = [];
  if (!isObject(doc)) return [`${file} is not a JSON object`];
  for (const k of Object.keys(doc)) if (!SWH_RECORD_MEMBERS.includes(k)) out.push(`${file} carries ${memberLabel(k)}, which the record format does not define`);
  for (const k of SWH_RECORD_MEMBERS) if (!Object.hasOwn(doc, k)) out.push(`${file} has no \`${k}\``);
  if (out.length) return out;
  if (doc.checkpoint !== `checkpoints/${name}.jws`) out.push(`${file}: \`checkpoint\` does not name the checkpoint beside it`);
  if (!(typeof doc.origin_url === 'string' && /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(doc.origin_url))) out.push(`${file}: \`origin_url\` is not a GitHub repository URL`);
  if (!(typeof doc.snapshot_swhid === 'string' && /^swh:1:snp:[0-9a-f]{40}$/.test(doc.snapshot_swhid))) out.push(`${file}: \`snapshot_swhid\` is not swh:1:snp: and 40 hex`);
  if (!isDateTime(doc.visit_date)) out.push(`${file}: \`visit_date\` is not an RFC 3339 date-time`);
  if (doc.visit_status !== 'full') out.push(`${file}: \`visit_status\` is not full`);
  if (!(doc.save_request_id === null || isUint(doc.save_request_id))) out.push(`${file}: \`save_request_id\` is neither null nor an integer`);
  if (!(doc.save_request_url === null || (typeof doc.save_request_url === 'string' && /^https:\/\/archive\.softwareheritage\.org\/api\/1\/origin\/save\/[0-9]+\/$/.test(doc.save_request_url)))) {
    out.push(`${file}: \`save_request_url\` is neither null nor a Software Heritage save-request URL`);
  }
  if (!(typeof doc.mirror_commit === 'string' && /^[0-9a-f]{40}$/.test(doc.mirror_commit))) out.push(`${file}: \`mirror_commit\` is not a 40-hex git commit id`);
  return out;
}
