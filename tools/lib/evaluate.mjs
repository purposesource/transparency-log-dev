// What one run of the mirror decides: the mirror as it stands, against what the edge served.
//
// THE RULES (plan §2 with corrections 3, 8 and 13):
//   - The mirror must be clean before anything is added. If it is not, the run stops red and
//     repairs nothing.
//   - A served copy that is a strict PREFIX of what is mirrored may be a stale cache read, and
//     is skipped while a cache can still explain it: inside the cache window counted from the
//     moment the mirror committed the longer copy (lib/spec.mjs CACHE_WINDOW_MS: latest.json
//     2 h, ct/{n}.json 26 h, jwks.json 25 h). After the window, or when the served copy was
//     generated LATER than the mirrored one (its generatedAt is newer), it is an incident:
//     the log shrank. A copy that is neither a prefix nor an extension is an incident at once.
//     Which segments exist is read from latest.json's `segment`, never by probing.
//   - A 404 is "not served now" (an edge cache can hold an absence). For a segment the mirror
//     already holds, that excuse lasts the segment's cache window, then it is an incident (a
//     published segment was removed). A segment that stays missing or open while a later one
//     is held is an incident 26 hours after the mirror first held the later one.
//   - A 5xx or no answer makes the run skip, green, with a warning.
//   - "Changed" means new entries, a numbered segment that grew, a new checkpoint, or a
//     key-set change. A run that sees only a new `generatedAt` commits nothing. When a run
//     does commit, latest.json and jwks.json are refreshed to the bytes served at that moment.
//   - On an incident nothing in the mirror moves; the served bytes become evidence under
//     incidents/, each file in full only if it passes its schema and the no-names rule,
//     otherwise only its SHA-256 and the reason.
//   - An EMPTY mirror whose origin serves only keys outside the environment's fence is a
//     setting error (PSN_ENV or PSN_ORIGIN), not an incident: red, nothing recorded.

import { sha256Hex } from './canonical.mjs';
import { parseCompact } from './jws.mjs';
import { compareKeySets } from './keys.mjs';
import { instantMs, parseJson } from './schema.mjs';
import { CACHE_WINDOW_MS, ENVIRONMENTS, KID_PATTERN, SERVED_PATHS } from './spec.mjs';
import { cloneState } from './state.mjs';
import { checkpointName, readFile, verifyState } from './verify-state.mjs';

const describe = (r) => (r.status ? `HTTP ${r.status}` : r.failure || 'no answer');
const iso = (ms) => new Date(ms).toISOString().slice(0, 19) + 'Z';
const hours = (ms) => `${ms / 3_600_000} hours`;

/**
 * @param {object} mirrored  the mirror's state (lib/state.mjs)
 * @param {object} served    { latest, segments: Map<n, r>, checkpointLatest, jwks, fetchedAt } where r = { status, bytes?, failure? }
 * @param {object} options
 * @param {'prod'|'dev'} options.env
 * @param {object} [options.clock]  when the mirror committed its copies, for the cache windows:
 *   { now: ms, committedAt(path): ms|null, heldSince(segment): ms|null }. committedAt is the
 *   commit date of the mirror's copy of `path`; heldSince is the commit date from which the
 *   mirror has held `segment` (or a later one) as its open segment. null means "not committed
 *   yet", which counts as just now. Without a clock (the --history walk, which flags every
 *   step backwards anyway) a short read is judged a stale read.
 * Returns { outcome, incidents, warnings, notices, changes, writes, evidence, stale, summary }.
 */
export function evaluate(mirrored, served, { env, clock = null }) {
  const result = {
    outcome: 'unchanged',
    incidents: [],
    warnings: [],
    notices: [],
    changes: [],
    writes: new Map(),
    evidence: [],
    stale: [],
    summary: null,
  };

  const base = verifyState(mirrored, { env });
  if (base.problems.length) {
    result.outcome = 'mirror-broken';
    result.incidents = base.problems;
    return result;
  }

  // ── what was served, and whether this run can judge it at all ───────────────────────────
  if (served.latest.status === 404) {
    if (mirrored.latest) {
      // The whole log answers 404: latest.json's window, counted from the mirrored copy.
      const since = committedAt(clock, SERVED_PATHS.latest);
      if (!insideWindow(clock, since, CACHE_WINDOW_MS.latest)) {
        result.outcome = 'incident';
        result.incidents = [`${SERVED_PATHS.latest} answers 404, and the mirror has held it since ${iso(since)}, longer than an edge cache holds an absence (${hours(CACHE_WINDOW_MS.latest)}): the published log is no longer served`];
        return result;
      }
      result.warnings.push(`the origin answers 404 for ${SERVED_PATHS.latest}, which the mirror holds; nothing was changed`);
    } else result.notices.push(`the log is not published at this origin yet (${SERVED_PATHS.latest} answers 404); nothing to mirror`);
    result.outcome = 'not-published';
    return result;
  }
  const unreadable = [];
  if (served.latest.status !== 200) unreadable.push(`${SERVED_PATHS.latest} (${describe(served.latest)})`);
  for (const [n, r] of served.segments ?? []) if (r.status !== 200 && r.status !== 404) unreadable.push(`${SERVED_PATHS.segment(n)} (${describe(r)})`);
  for (const [path, r] of [[SERVED_PATHS.checkpointLatest, served.checkpointLatest], [SERVED_PATHS.jwks, served.jwks]]) {
    if (r && r.status !== 200 && r.status !== 404) unreadable.push(`${path} (${describe(r)})`);
  }
  if (unreadable.length) {
    result.outcome = 'unreadable';
    result.warnings.push(`could not read ${unreadable.join(', ')}; this says nothing about the log, and the next run reads it again`);
    return result;
  }

  // ── a setting error, not an incident: an empty mirror pointed at the other plane ─────────
  const fence = ENVIRONMENTS[env].kidPrefix;
  if (isEmpty(mirrored)) {
    const kids = servedKids(served);
    if (kids.length && kids.every((kid) => !kid.startsWith(fence))) {
      result.outcome = 'misconfigured';
      result.incidents = [
        `every key the origin serves (${[...new Set(kids)].join(', ')}) is outside the ${env} fence (${fence}…), and the mirror is empty: PSN_ENV or PSN_ORIGIN is probably set wrong. Nothing was recorded.`,
      ];
      return result;
    }
  }

  // Every served file on its own; the evidence an incident would keep.
  const fileProblems = [];
  const read = (r, path, kind) => {
    const file = readFile(r.bytes, path, kind, { env });
    fileProblems.push(...file.schema, ...file.pii, ...file.form);
    const clean = file.schema.length === 0 && file.pii.length === 0;
    result.evidence.push({
      path,
      bytes: r.bytes,
      sha256: sha256Hex(r.bytes),
      include: clean,
      why: clean ? null : [...file.schema, ...file.pii][0],
    });
    return file.schema.length || file.pii.length || file.form.length ? null : file;
  };

  /**
   * A served copy older than the mirrored one: a stale read while a cache can explain it,
   * otherwise an incident. `newer` is true when the served copy was generated later.
   */
  const shortRead = (path, windowMs, newer, what) => {
    if (newer) {
      fileProblems.push(`${path} as served ${what}, and it was generated later than the mirrored copy (a newer generatedAt), so it is not a cached older copy`);
      return;
    }
    const since = committedAt(clock, path);
    if (!insideWindow(clock, since, windowMs)) {
      fileProblems.push(`${path} as served ${what}, and the mirror has held the longer copy since ${iso(since)}, longer than the edge caches this file (${hours(windowMs)}), so it is not a cached older copy`);
      return;
    }
    result.stale.push(path);
    result.notices.push(`${path} as served is behind the mirrored copy (a stale cache read); kept the mirrored copy`);
  };

  const next = cloneState(mirrored);
  const extra = [];
  const refresh = new Map();
  const adopt = (path, bytes, change) => {
    result.writes.set(path, bytes);
    if (change) result.changes.push(change);
  };

  // ── ct/latest.json ────────────────────────────────────────────────────────────────────────
  const latestFile = read(served.latest, SERVED_PATHS.latest, 'latest');
  const mLatest = base.view.latestDoc;
  if (latestFile) {
    const s = latestFile.doc;
    if (!mLatest) {
      next.latest = served.latest.bytes;
      adopt(SERVED_PATHS.latest, served.latest.bytes, `${SERVED_PATHS.latest} (new)`);
    } else if (s.segment > mLatest.segment || (s.segment === mLatest.segment && s.entries.length > mLatest.entries.length)) {
      extra.push({ label: `the previously mirrored ${SERVED_PATHS.latest}`, doc: mLatest });
      next.latest = served.latest.bytes;
      adopt(SERVED_PATHS.latest, served.latest.bytes, `${SERVED_PATHS.latest} (head seq ${lastSeq(mLatest)} → ${lastSeq(s)})`);
    } else {
      extra.push({ label: `${SERVED_PATHS.latest} as served`, doc: s });
      if (s.segment === mLatest.segment && s.entries.length === mLatest.entries.length) {
        if (!served.latest.bytes.equals(mirrored.latest) && instantMs(s.generatedAt) > instantMs(mLatest.generatedAt)) refresh.set(SERVED_PATHS.latest, served.latest.bytes);
      } else {
        shortRead(
          SERVED_PATHS.latest,
          CACHE_WINDOW_MS.latest,
          instantMs(s.generatedAt) > instantMs(mLatest.generatedAt),
          `ends at head seq ${lastSeq(s)} in segment ${s.segment}, behind the mirrored copy (head seq ${lastSeq(mLatest)} in segment ${mLatest.segment})`,
        );
      }
    }
  }

  // ── ct/{n}.json, for every segment latest.json implies ─────────────────────────────────────
  for (const [n, r] of [...(served.segments ?? [])].sort((a, b) => a[0] - b[0])) {
    const path = SERVED_PATHS.segment(n);
    if (r.status === 404) {
      if (mirrored.segments.has(n)) {
        const since = committedAt(clock, path);
        if (!insideWindow(clock, since, CACHE_WINDOW_MS.segment)) {
          fileProblems.push(`${path} answers 404, and the mirror has held it since ${iso(since)}, longer than an edge cache holds an absence (${hours(CACHE_WINDOW_MS.segment)}): a published segment is no longer served`);
          continue;
        }
        result.stale.push(path);
      }
      result.warnings.push(`${path} answers 404 although ${SERVED_PATHS.latest} names segment ${latestFile?.doc.segment ?? n} (a cached absence, or not published yet); kept what the mirror holds`);
      continue;
    }
    const file = read(r, path, 'numbered');
    if (!file) continue;
    const s = file.doc;
    const m = mirrored.segments.has(n) ? readFile(mirrored.segments.get(n), path, 'numbered').doc : null;
    if (!m) {
      next.segments.set(n, r.bytes);
      adopt(path, r.bytes, `${path} (new, ${s.entries.length} entries)`);
    } else if (s.entries.length > m.entries.length) {
      extra.push({ label: `the previously mirrored ${path}`, doc: m });
      next.segments.set(n, r.bytes);
      adopt(path, r.bytes, `${path} (${m.entries.length} → ${s.entries.length} entries)`);
    } else {
      extra.push({ label: `${path} as served`, doc: s });
      // A numbered segment carries no generatedAt, so only the window can tell.
      if (s.entries.length < m.entries.length) shortRead(path, CACHE_WINDOW_MS.segment, false, `holds ${s.entries.length} entries, fewer than the ${m.entries.length} the mirror holds`);
    }
  }

  // ── jwks.json (before the checkpoint, which is verified against it) ─────────────────────────
  if (served.jwks?.status === 404) {
    if (mirrored.jwks) {
      const since = committedAt(clock, SERVED_PATHS.jwks);
      if (!insideWindow(clock, since, CACHE_WINDOW_MS.jwks)) fileProblems.push(`${SERVED_PATHS.jwks} answers 404, and the mirror has held it since ${iso(since)}, longer than an edge cache holds an absence (${hours(CACHE_WINDOW_MS.jwks)}): the key set is no longer served`);
      else result.warnings.push(`${SERVED_PATHS.jwks} answers 404; kept what the mirror holds`);
    } else result.warnings.push(`${SERVED_PATHS.jwks} answers 404; kept what the mirror holds`);
  } else if (served.jwks) {
    const file = read(served.jwks, SERVED_PATHS.jwks, 'jwks');
    if (file) {
      const mKeys = base.view.keyDoc;
      const cmp = compareKeySets(mKeys, file.doc);
      result.notices.push(...cmp.notices);
      if (cmp.verdict === 'incident') fileProblems.push(...cmp.problems);
      else if (cmp.verdict === 'new' || cmp.verdict === 'advance') {
        next.jwks = served.jwks.bytes;
        adopt(SERVED_PATHS.jwks, served.jwks.bytes, `${SERVED_PATHS.jwks} (${cmp.verdict === 'new' ? 'new' : 'keys changed'})`);
      } else if (cmp.verdict === 'stale') {
        const older = [...cmp.gone.map((kid) => `${kid} missing`), ...cmp.backwards.map((kid) => `${kid}'s standing moved back`)].join(', ');
        shortRead(SERVED_PATHS.jwks, CACHE_WINDOW_MS.jwks, laterThan(file.doc.generatedAt, mKeys.generatedAt), `is an older version of the mirrored key set (${older}); a kid never leaves the key set`);
      } else if (cmp.verdict === 'same' && !served.jwks.bytes.equals(mirrored.jwks) && instantMs(file.doc.generatedAt) >= instantMs(mKeys.generatedAt)) {
        refresh.set(SERVED_PATHS.jwks, served.jwks.bytes);
      }
    }
  }

  // ── ct/checkpoint-latest.json, and checkpoints/ ──────────────────────────────────────────────
  if (served.checkpointLatest?.status === 404) {
    if (mirrored.checkpointLatest) result.warnings.push(`${SERVED_PATHS.checkpointLatest} answers 404, and the mirror holds one; kept what the mirror holds`);
    else result.notices.push(`no checkpoint is published at this origin yet (${SERVED_PATHS.checkpointLatest} answers 404)`);
  } else if (served.checkpointLatest) {
    const file = read(served.checkpointLatest, SERVED_PATHS.checkpointLatest, 'checkpoint-artifact');
    if (file) {
      const { header, payload } = file.token;
      const name = checkpointName(payload.asOf, payload.headSeq);
      const jwsBytes = Buffer.from(file.doc.jws, 'latin1');
      const held = mirrored.checkpoints.get(name);
      let accepted = false;
      if (!header.kid.startsWith(fence)) {
        fileProblems.push(`${SERVED_PATHS.checkpointLatest}: signed under ${header.kid}, outside the ${env} fence (${fence}…)`);
      } else if (held && !held.equals(jwsBytes)) {
        fileProblems.push(`checkpoints/${name}.jws is already mirrored with a different token; checkpoint files are never rewritten`);
      } else if (held) {
        accepted = true;
      } else {
        const keyDoc = next.jwks ? readFile(next.jwks, SERVED_PATHS.jwks, 'jwks', { env }).doc : null;
        if (!keyDoc?.keys.some((k) => k.kid === header.kid)) {
          result.warnings.push(`the served checkpoint ${name} is signed under ${header.kid}, which the key set does not carry yet; not mirrored this run, tried again on the next`);
        } else {
          next.checkpoints.set(name, jwsBytes);
          adopt(`checkpoints/${name}.jws`, jwsBytes, `checkpoints/${name}.jws (new)`);
          accepted = true;
        }
      }
      const mCkp = base.view.ckpLatest;
      if (accepted) {
        if (!mCkp || instantMs(payload.asOf) > instantMs(mCkp.token.payload.asOf)) {
          next.checkpointLatest = served.checkpointLatest.bytes;
          adopt(SERVED_PATHS.checkpointLatest, served.checkpointLatest.bytes, mCkp ? `${SERVED_PATHS.checkpointLatest} (newer checkpoint)` : `${SERVED_PATHS.checkpointLatest} (new)`);
        } else if (mCkp.doc.jws === file.doc.jws) {
          if (!served.checkpointLatest.bytes.equals(mirrored.checkpointLatest)) refresh.set(SERVED_PATHS.checkpointLatest, served.checkpointLatest.bytes);
        } else {
          result.notices.push(`${SERVED_PATHS.checkpointLatest} as served is an older checkpoint than the mirrored one (a stale cache read)`);
        }
      }
    }
  }

  // ── the state the served bytes would make, held to every rule ──────────────────────────────
  const check = verifyState(next, { env, extra });
  const added = check.problems.filter((p) => !base.problems.includes(p));
  // A segment still missing or open while a later one is held: an incident once the mirror
  // has held the later segment for longer than the edge caches a numbered segment.
  const overdue = [];
  for (const w of check.view.waits) {
    const since = clock ? clock.heldSince(w.segment + 1) : null;
    if (since === null || insideWindow(clock, since, CACHE_WINDOW_MS.rollover)) continue;
    overdue.push(
      w.entries === null
        ? `segment ${w.segment} is still not served, and the mirror has held a later segment since ${iso(since)}, longer than the edge caches a numbered segment (${hours(CACHE_WINDOW_MS.rollover)}): a closed segment is missing`
        : `segment ${w.segment} is still served open (${w.entries} entries), and the mirror has held a later segment since ${iso(since)}, longer than the edge caches a numbered segment (${hours(CACHE_WINDOW_MS.rollover)}): its closed copy is missing`,
    );
  }
  result.incidents = [...new Set([...fileProblems, ...added, ...overdue])];
  result.warnings.push(...check.pending);
  // Notes are never failures. Those the served bytes add are shown once, as warnings, in the
  // run that adopts them; tools/verify.mjs prints every note on every check.
  result.warnings.push(...check.notes.filter((n) => !base.notes.includes(n)));

  const ckps = check.view.checkpoints;
  result.summary = {
    headSeq: check.view.headSeq,
    segment: check.view.latestSegment,
    checkpointAsOf: ckps.length ? ckps[ckps.length - 1].asOf : null,
    latestSha256: sha256Hex(served.latest.bytes),
    fetchedAt: served.fetchedAt,
  };

  if (result.incidents.length) {
    result.outcome = 'incident';
    result.writes = new Map();
    result.changes = [];
  } else if (result.changes.length) {
    result.outcome = 'changed';
    for (const [path, bytes] of refresh) if (!result.writes.has(path)) result.writes.set(path, bytes);
  } else {
    result.outcome = 'unchanged';
    result.writes = new Map();
  }
  return result;
}

function lastSeq(doc) {
  return doc.entries.length ? doc.entries[doc.entries.length - 1].seq : `none (segment ${doc.segment})`;
}

/** When the mirror committed its copy of `path`; uncommitted (or no clock) counts as now. */
function committedAt(clock, path) {
  if (!clock) return null;
  return clock.committedAt(path) ?? clock.now;
}

/** True while a cache could still hold a copy older than one the mirror committed at `since`. */
function insideWindow(clock, since, windowMs) {
  if (!clock || since === null) return true;
  return clock.now - since <= windowMs;
}

/** True when both are date-times and `a` is later than `b`. */
function laterThan(a, b) {
  const x = instantMs(a);
  const y = instantMs(b);
  return x !== null && y !== null && x > y;
}

function isEmpty(state) {
  return !state.latest && !state.jwks && !state.checkpointLatest && state.segments.size === 0 && state.checkpoints.size === 0;
}

/** Every well-formed kid the origin served: the key set's and the checkpoint's. Read leniently, before any schema check. */
function servedKids(served) {
  const kids = [];
  if (served.jwks?.status === 200) {
    const keys = parseJson(served.jwks.bytes).value?.keys;
    if (Array.isArray(keys)) for (const k of keys) if (typeof k?.kid === 'string' && KID_PATTERN.test(k.kid)) kids.push(k.kid);
  }
  if (served.checkpointLatest?.status === 200) {
    const jws = parseJson(served.checkpointLatest.bytes).value?.jws;
    const kid = typeof jws === 'string' ? parseCompact(jws).header?.kid : null;
    if (typeof kid === 'string' && KID_PATTERN.test(kid)) kids.push(kid);
  }
  return kids;
}
