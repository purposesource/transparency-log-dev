// The public contract this mirror checks against, written down as tables.
//
// Every value here is read from the PUBLIC specification repository
// (github.com/purposesource/spec): schemas/ct-segment.v1.json, schemas/ct-checkpoint.v1.json
// and openapi/edge-public.v1.yaml (components Jwks and CtCheckpointArtifact). Nothing is
// copied from a private repository. When the specification changes, this file changes in the
// same step; each table names the version it follows.

/** The specification versions these tables follow. */
export const SPEC_VERSIONS = Object.freeze({
  ctSegment: '1.3.0',
  ctCheckpoint: '1.0.0',
});

/** FS08-111 as ct-segment.v1 states it: a closed segment holds exactly this many entries. */
export const ENTRIES_PER_SEGMENT = 10000;

/**
 * The entry kinds, and what each one's `ref` and `h` must be.
 *
 * ct-segment.v1 1.3.0 closes `kind` to issue, revoke and status. `record` is NOT in 1.3.0: the
 * recording-instant build adds it (a waiver's recording instant, `ref` = the waiver
 * certificate's issue entry, `h` over the entry's own members like a revocation). It is
 * accepted here already, so the mirror does not raise a false incident on the day the first
 * `record` entry is published (plan correction 4).
 *
 * - `refersTo: null`      the entry references nothing: `ref` must be null.
 * - `refersTo: 'earlier'` `ref` must be the `h` of an EARLIER entry in this log.
 * - `ownHash: true`       `h` is the SHA-256 of the RFC 8785 text of the entry's own members
 *                         other than `seq` and `h` ({kind, ref, ts, typ}), as ct-segment.v1
 *                         defines it for revoke and status.
 */
export const ENTRY_KINDS = Object.freeze({
  issue: Object.freeze({ refersTo: null, ownHash: false, since: '1.0.0' }),
  revoke: Object.freeze({ refersTo: 'earlier', ownHash: true, since: '1.0.0' }),
  status: Object.freeze({ refersTo: 'earlier', ownHash: true, since: '1.0.0' }),
  record: Object.freeze({ refersTo: 'earlier', ownHash: true, since: 'not yet in the specification' }),
});

/** ct-segment.v1 1.3.0 `$defs.entry.typ`. */
export const ENTRY_TYPS = Object.freeze([
  'contributor',
  'steward',
  'supporter',
  'license-status',
  'topup',
  'entitlement-record',
  'ct-checkpoint',
]);

/** The six members of an entry, in the order the platform publishes them. */
export const ENTRY_MEMBERS = Object.freeze(['seq', 'h', 'typ', 'kind', 'ref', 'ts']);

/** The members of a numbered segment, in the order the platform publishes them. */
export const SEGMENT_MEMBERS = Object.freeze(['schemaVersion', 'segment', 'startSeq', 'prevSegmentSha256', 'entries']);

/** Every member ct-segment.v1 allows at the top level (additionalProperties: false). */
export const SEGMENT_ALLOWED = Object.freeze([...SEGMENT_MEMBERS, 'generatedAt', 'source', 'closed']);

/** ct-segment.v1 `source`, and the same enum on the key set. */
export const SOURCES = Object.freeze(['registry-v0', 'sample', 'fixture', 'platform']);

/** ct-checkpoint.v1: the payload's members, in the contract's order. The first four are required. */
export const CHECKPOINT_MEMBERS = Object.freeze(['asOf', 'headSeq', 'headSegment', 'headSegmentSha256', 'kid', 'iss']);
export const CHECKPOINT_REQUIRED = Object.freeze(['asOf', 'headSeq', 'headSegment', 'headSegmentSha256']);

/** ct-checkpoint.v1 x-psn.signature. */
export const CHECKPOINT_ALG = 'ES256';
export const CHECKPOINT_TYP = 'application/psn-ct-checkpoint+jws';

/** The protected-header members a checkpoint token carries ({alg, kid, typ}). */
export const CHECKPOINT_HEADER_MEMBERS = Object.freeze(['alg', 'kid', 'typ']);

/** edge-public.v1 CtCheckpointArtifact, in the published order. */
export const CHECKPOINT_ARTIFACT_MEMBERS = Object.freeze(['schemaVersion', 'generatedAt', 'jws', 'payload']);

/** ct-checkpoint.v1 `$defs.kid` and the Jwks key item's `kid`. */
export const KID_PATTERN = /^psn-(dev|prod|sandbox)-[0-9]{4}-[0-9]+$/;

/** edge-public.v1 Jwks. */
export const JWKS_ALLOWED = Object.freeze(['schemaVersion', 'generatedAt', 'source', 'sandbox', 'keys']);
export const KEY_MATERIAL = Object.freeze(['kty', 'crv', 'x', 'y', 'kid', 'use', 'alg']);
export const KEY_STANDING = Object.freeze(['psn:status', 'psn:validityWindow']);
export const KEY_STATUSES = Object.freeze(['active', 'retired', 'compromised']);

/**
 * The environment fence (the signer's S5 rule): a prod log is signed only under psn-prod-
 * keys and a dev log only under psn-dev- keys, and neither key set carries the other's keys
 * (FS08-103: the planes never borrow each other's keys).
 */
export const ENVIRONMENTS = Object.freeze({
  prod: Object.freeze({ kidPrefix: 'psn-prod-' }),
  dev: Object.freeze({ kidPrefix: 'psn-dev-' }),
});

/** The four files the mirror reads, as the edge serves them. */
export const SERVED_PATHS = Object.freeze({
  latest: 'ct/latest.json',
  checkpointLatest: 'ct/checkpoint-latest.json',
  jwks: 'jwks.json',
  segment: (n) => `ct/${n}.json`,
});

/** The edge routes numbered segments as /ct/(\d{1,6}).json. */
export const MAX_SEGMENT = 999999;

const HOUR_MS = 60 * 60 * 1000;

/**
 * How long a served copy SHORTER than the mirrored one may still be a cached older copy,
 * counted from the moment the mirror committed the longer copy (plan correction 3). After
 * that, no cache can still hold the older copy, so a shorter copy means the log shrank.
 *   latest    /ct/latest.json is cached for 300 seconds; two hours leaves room for a late run.
 *   segment   /ct/{n}.json is cached for a day (s-maxage=86400); 26 hours is the platform's own
 *             allowance (CtConsistency RolloverAllowance), also used for a segment that
 *             closed (or went missing) while a later one is already served.
 *   jwks      /jwks.json is cached for an hour, and for up to a day more while the origin errs
 *             (stale-if-error=86400).
 */
export const CACHE_WINDOW_MS = Object.freeze({
  latest: 2 * HOUR_MS,
  segment: 26 * HOUR_MS,
  rollover: 26 * HOUR_MS,
  jwks: 25 * HOUR_MS,
});

export const SHA256_HEX = /^[0-9a-f]{64}$/;
