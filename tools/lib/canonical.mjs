// Hashing and the two byte forms the log is built from.
//
// 1. RFC 8785 (JCS) canonical JSON: what a checkpoint payload is signed in
//    (ct-checkpoint.v1 x-psn.signature) and what a revoke/status entry's `h` is taken over
//    (ct-segment.v1 `$defs.entry.h`).
// 2. The PUBLISHED form of a segment document: two-space indentation, LF line ends, one
//    trailing newline, members in the platform's order. The public specification does not
//    define this serialisation, yet `prevSegmentSha256` and a checkpoint's
//    `headSegmentSha256` are taken over exactly these bytes. It is pinned here to what the
//    platform's renderer writes (`JSON.stringify(document, null, 2) + "\n"` for documents of
//    integers, null and ASCII strings) and to the test vectors in tests/fixtures (the first
//    signed dev checkpoint and the segment it commits to). See README, "Re-rendering a
//    segment".

import { createHash } from 'node:crypto';

import { ENTRY_MEMBERS, SEGMENT_MEMBERS } from './spec.mjs';

/** Lowercase hex SHA-256 of bytes or of a string's UTF-8 bytes. */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * RFC 8785 canonical JSON text. Integers only (every number the log and its checkpoints
 * carry is an integer, and a float's shortest round-trip form is where implementations
 * disagree), strings serialised as ECMAScript JSON.stringify does (RFC 8785 §3.2.2.2),
 * object members sorted by UTF-16 code units (§3.2.3).
 */
export function jcs(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('jcs: only safe integers are canonicalised here');
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
  }
  throw new Error(`jcs: a ${typeof value} has no canonical form`);
}

/** The published bytes of a document: two-space indented, LF, one trailing newline. */
export function published(document) {
  return Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
}

function entryBody(entry) {
  const out = {};
  for (const member of ENTRY_MEMBERS) out[member] = entry[member];
  return out;
}

/** A numbered segment's body, in the platform's member order, holding `entries`. */
export function segmentBody(doc, entries = doc.entries) {
  const body = {};
  for (const member of SEGMENT_MEMBERS) body[member] = member === 'entries' ? entries.map(entryBody) : doc[member];
  return body;
}

/** The bytes of `/ct/{n}.json` for this segment document (or for `entries`, when given). */
export function renderSegment(doc, entries = doc.entries) {
  return published(segmentBody(doc, entries));
}

/** The bytes of `/ct/latest.json`: the segment body, then `generatedAt`, then `closed`. */
export function renderLatest(doc) {
  const body = segmentBody(doc);
  body.generatedAt = doc.generatedAt;
  body.closed = doc.closed;
  return published(body);
}

/**
 * The head segment as it stood when a checkpoint was taken: the entries up to and
 * including `headSeq`, re-rendered as `/ct/{n}.json`. A numbered segment carries nothing but
 * its entries and its link to the segment before, so this is the exact document the
 * checkpoint's `headSegmentSha256` was taken over.
 */
export function renderCut(doc, headSeq) {
  return renderSegment(
    doc,
    doc.entries.filter((e) => e.seq <= headSeq),
  );
}

/** A revoke/status/record entry's own `h`: SHA-256 of JCS({kind, ref, ts, typ}). */
export function ownEntryHash(entry) {
  return sha256Hex(jcs({ kind: entry.kind, ref: entry.ref, ts: entry.ts, typ: entry.typ }));
}

/** `/ct/checkpoint-latest.json` in the published order: envelope, `jws`, then the payload in the contract's order. */
export function renderCheckpointArtifact(doc, payloadOrder) {
  const payload = {};
  for (const member of payloadOrder) if (Object.hasOwn(doc.payload, member)) payload[member] = doc.payload[member];
  return published({ schemaVersion: doc.schemaVersion, generatedAt: doc.generatedAt, jws: doc.jws, payload });
}
