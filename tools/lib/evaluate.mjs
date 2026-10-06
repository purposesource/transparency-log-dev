// What one run of the mirror decides: the mirror as it stands, against what the edge served.
//
// THE RULES (plan §2 with corrections 3, 8 and 13):
//   - The mirror must be clean before anything is added. If it is not, the run stops red and
//     repairs nothing.
//   - A served copy that is a strict PREFIX of what is mirrored is a stale cache read: skipped.
//     Only a copy that is neither a prefix nor an extension is an incident. Which segments
//     exist is read from latest.json's `segment`, never by probing.
//   - A 404 is "not served now" (an edge cache can hold an absence), never an incident; a
//     5xx or no answer makes the run skip, green, with a warning.
//   - "Changed" means new entries, a numbered segment that grew, a new checkpoint, or a
//     key-set change. A run that sees only a new `generatedAt` commits nothing. When a run
//     does commit, latest.json and jwks.json are refreshed to the bytes served at that moment.
//   - On an incident nothing in the mirror moves; the served bytes become evidence under
//     incidents/, each file in full only if it passes its schema and the no-names rule,
//     otherwise only its SHA-256 and the reason.

import { sha256Hex } from './canonical.mjs';
import { compareKeySets } from './keys.mjs';
import { instantMs } from './schema.mjs';
import { SERVED_PATHS } from './spec.mjs';
import { cloneState } from './state.mjs';
import { checkpointName, readFile, verifyState } from './verify-state.mjs';

const describe = (r) => (r.status ? `HTTP ${r.status}` : r.failure || 'no answer');

/**
 * @param {object} mirrored  the mirror's state (lib/state.mjs)
 * @param {object} served    { latest, segments: Map<n, r>, checkpointLatest, jwks, fetchedAt } where r = { status, bytes?, failure? }
 * @param {{env: 'prod'|'dev'}} options
 */
export function evaluate(mirrored, served, { env }) {
  const result = {
    outcome: 'unchanged',
    incidents: [],
    warnings: [],
    notices: [],
    changes: [],
    writes: new Map(),
    evidence: [],
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
    if (mirrored.latest) result.warnings.push(`the origin answers 404 for ${SERVED_PATHS.latest}, which the mirror holds; nothing was changed`);
    else result.notices.push(`the log is not published at this origin yet (${SERVED_PATHS.latest} answers 404); nothing to mirror`);
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
        result.notices.push(`${SERVED_PATHS.latest} as served is behind the mirrored copy (a stale cache read); kept the mirrored copy`);
      }
    }
  }

  // ── ct/{n}.json, for every segment latest.json implies ─────────────────────────────────────
  for (const [n, r] of [...(served.segments ?? [])].sort((a, b) => a[0] - b[0])) {
    const path = SERVED_PATHS.segment(n);
    if (r.status === 404) {
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
      if (s.entries.length < m.entries.length) result.notices.push(`${path} as served is behind the mirrored copy (a stale cache read); kept the mirrored copy`);
    }
  }

  // ── jwks.json (before the checkpoint, which is verified against it) ─────────────────────────
  if (served.jwks?.status === 404) {
    result.warnings.push(`${SERVED_PATHS.jwks} answers 404; kept what the mirror holds`);
  } else if (served.jwks) {
    const file = read(served.jwks, SERVED_PATHS.jwks, 'jwks');
    if (file) {
      const cmp = compareKeySets(base.view.keyDoc, file.doc);
      result.notices.push(...cmp.notices);
      if (cmp.verdict === 'incident') fileProblems.push(...cmp.problems);
      else if (cmp.verdict === 'new' || cmp.verdict === 'advance') {
        next.jwks = served.jwks.bytes;
        adopt(SERVED_PATHS.jwks, served.jwks.bytes, `${SERVED_PATHS.jwks} (${cmp.verdict === 'new' ? 'new' : 'keys changed'})`);
      } else if (cmp.verdict === 'same' && !served.jwks.bytes.equals(mirrored.jwks) && instantMs(file.doc.generatedAt) >= instantMs(base.view.keyDoc.generatedAt)) {
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
      if (held && !held.equals(jwsBytes)) {
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
  result.incidents = [...new Set([...fileProblems, ...added])];
  result.warnings.push(...check.pending);
  result.notices.push(...check.notes);

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
