// The key set only grows (plan correction 5; FS08-102 and CERT-022: historical keys stay for
// ever). A kid never disappears, a kid's key material never changes, and a new kid is
// flagged. A key's STANDING (psn:status, psn:validityWindow) may move forward (active to
// retired to compromised, a window that closes); that is a key-set change and is committed.
//
// A served key set that is an OLDER version of the mirrored one (a kid missing, or a
// standing that moved backwards, and nothing newer) is a stale cache read, not a shrinking
// set: /jwks.json is cached for an hour and, while the origin errs, for up to a day
// (stale-if-error=86400). Only a set that is neither older nor newer, or that changes key
// material, is an incident.
//
// THIS IS NOT THE OUT-OF-BAND KEY CHANNEL. This repository copies the key set the edge
// serves; anyone who could substitute both the edge's checkpoint and its key set would pass
// the signature check here. The out-of-band copy is the key set committed with signed
// commits to the public specification repository (CERT-021, FS08-102).

import { KEY_MATERIAL, KEY_STATUSES } from './spec.mjs';
import { instantMs } from './schema.mjs';

const byKid = (doc) => new Map((doc?.keys ?? []).map((k) => [k.kid, k]));

function standingOf(key) {
  const w = key['psn:validityWindow'] ?? null;
  return {
    status: Object.hasOwn(key, 'psn:status') ? key['psn:status'] : null,
    notBefore: w?.notBefore ?? null,
    notAfter: w && Object.hasOwn(w, 'notAfter') ? w.notAfter : null,
  };
}

/** 'same', 'later', 'earlier' or 'changed' (moved in a way that is neither, e.g. a new notBefore). */
function compareStanding(a, b) {
  const sa = standingOf(a);
  const sb = standingOf(b);
  const same = (x, y) => x === y || (x !== null && y !== null && instantMs(x) === instantMs(y));
  if (sa.status === sb.status && same(sa.notBefore, sb.notBefore) && same(sa.notAfter, sb.notAfter)) return 'same';
  if (!same(sa.notBefore, sb.notBefore)) return 'changed';
  const ra = KEY_STATUSES.indexOf(sa.status);
  const rb = KEY_STATUSES.indexOf(sb.status);
  const closes = sa.notAfter === null && sb.notAfter !== null;
  const opens = sa.notAfter !== null && sb.notAfter === null;
  const moved = sa.notAfter !== null && sb.notAfter !== null && !same(sa.notAfter, sb.notAfter);
  if (rb >= ra && !opens && !moved && (rb > ra || closes)) return 'later';
  if (rb <= ra && !closes && !moved && (rb < ra || opens)) return 'earlier';
  return 'changed';
}

/**
 * How the served key set relates to the mirrored one:
 *   { verdict: 'new' | 'same' | 'advance' | 'stale' | 'incident', problems, notices }
 */
export function compareKeySets(mirroredDoc, servedDoc) {
  if (!mirroredDoc) {
    return { verdict: 'new', problems: [], notices: [...byKid(servedDoc).keys()].map((kid) => `the key set carries ${kid} (first copy)`) };
  }
  const before = byKid(mirroredDoc);
  const after = byKid(servedDoc);
  const problems = [];
  const notices = [];
  let older = 0;
  let newer = 0;
  for (const [kid, key] of before) {
    const now = after.get(kid);
    if (!now) {
      older++;
      continue;
    }
    const changed = KEY_MATERIAL.filter((m) => key[m] !== now[m]);
    if (changed.length) {
      problems.push(`jwks.json: the key material of ${kid} changed (${changed.join(', ')}); a key's material never changes`);
      continue;
    }
    const standing = compareStanding(key, now);
    if (standing === 'later') {
      newer++;
      notices.push(`jwks.json: the standing of ${kid} moved forward (now ${now['psn:status'] ?? 'no status'})`);
    } else if (standing === 'earlier') {
      older++;
    } else if (standing === 'changed') {
      newer++;
      notices.push(`jwks.json: the standing of ${kid} changed in a way that is neither forward nor back (check its window)`);
    }
  }
  for (const kid of after.keys()) {
    if (!before.has(kid)) {
      newer++;
      notices.push(`jwks.json: a new key appears, ${kid}`);
    }
  }
  if (problems.length) return { verdict: 'incident', problems, notices };
  if (older && newer) {
    const gone = [...before.keys()].filter((kid) => !after.has(kid));
    return {
      verdict: 'incident',
      problems: [
        gone.length
          ? `jwks.json: ${gone.join(', ')} disappeared from a key set that also changed otherwise; a kid never leaves the key set`
          : 'jwks.json: a key standing moved backwards in a key set that also changed otherwise',
      ],
      notices,
    };
  }
  if (older) return { verdict: 'stale', problems: [], notices: ['jwks.json as served is an older version of the mirrored key set (a stale cache read); kept the mirrored copy'] };
  if (newer) return { verdict: 'advance', problems: [], notices };
  return { verdict: 'same', problems: [], notices: [] };
}
