#!/usr/bin/env node
// Verifies a checkout of this repository, offline, with Node.js alone (22 or later; no npm
// packages).
//
//   node tools/verify.mjs --env prod            the files as they stand
//   node tools/verify.mjs --env prod --history  and every commit against the one before it
//
// What it checks is listed in README.md ("What the verifier checks"). Exit code 0 when every
// check holds, 1 when one does not. A "pending" line is a check that cannot run yet because a
// copy is still short (the edge caches a numbered segment for up to a day); it is not a failure.

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { evaluate } from './lib/evaluate.mjs';
import { git, parseArgs } from './lib/runtime.mjs';
import { ENVIRONMENTS, SERVED_PATHS } from './lib/spec.mjs';
import { emptyState, readState, readStateAt, safePath } from './lib/state.mjs';
import { verifyState } from './lib/verify-state.mjs';

/** Treats a later state as what was "served" to the earlier one, so the mirror's own growth rules judge each step. */
function asServed(state) {
  const r = (bytes) => (bytes ? { status: 200, bytes } : { status: 404 });
  return {
    latest: r(state.latest),
    segments: new Map([...state.segments].map(([n, b]) => [n, r(b)])),
    checkpointLatest: r(state.checkpointLatest),
    jwks: r(state.jwks),
    fetchedAt: null,
  };
}

/** History: every commit that touched the log, held against the commit before it. */
export function verifyHistory(dir, env) {
  const problems = [];
  const commits = git(dir, ['rev-list', '--reverse', '--first-parent', 'HEAD', '--', 'ct', 'checkpoints', 'jwks.json']).split('\n').filter(Boolean);
  let previous = emptyState();
  let previousCommit = null;
  for (const commit of commits) {
    const state = readStateAt(dir, commit);
    const at = commit.slice(0, 12);
    // Every commit's own layout: a file that does not belong (a colon in a checkpoint name, a
    // stray under ct/ or checkpoints/) fails in the commit that holds it, even when a later
    // commit removed it or the checkout cannot hold it.
    for (const path of state.strays) problems.push(`${at}: ${safePath(path)} does not belong in the mirror's layout`);
    // Files may only be added or grow: nothing under the layout disappears.
    for (const [n] of previous.segments) if (!state.segments.has(n)) problems.push(`${at}: ${SERVED_PATHS.segment(n)} was removed`);
    for (const [name, bytes] of previous.checkpoints) {
      if (!state.checkpoints.has(name)) problems.push(`${at}: checkpoints/${name}.jws was removed`);
      else if (!state.checkpoints.get(name).equals(bytes)) problems.push(`${at}: checkpoints/${name}.jws was rewritten`);
    }
    for (const [name, bytes] of previous.swhRecords) {
      if (!state.swhRecords.has(name)) problems.push(`${at}: checkpoints/${name}.swh.json was removed`);
      else if (!state.swhRecords.get(name).equals(bytes)) problems.push(`${at}: checkpoints/${name}.swh.json was rewritten`);
    }
    if (previous.jwks && !state.jwks) problems.push(`${at}: jwks.json was removed`);
    if (previous.latest && !state.latest) problems.push(`${at}: ct/latest.json was removed`);
    // The growth rules the mirror applies when it reads the edge, applied to this step.
    if (previousCommit) {
      // Strays are reported above, once per commit that holds them; the step judges the layout's files.
      const step = evaluate({ ...previous, strays: [] }, asServed(state), { env });
      if (step.outcome === 'incident' || step.outcome === 'mirror-broken' || step.outcome === 'misconfigured') {
        problems.push(...step.incidents.map((p) => `${at} (after ${previousCommit.slice(0, 12)}): ${p}`));
      }
      // A step the mirror would call stale moved backwards: the commit replaced newer bytes with older ones.
      if (step.stale.length) problems.push(`${at}: ${step.stale.join(', ')} went back to an older version than the commit before held`);
    }
    previous = state;
    previousCommit = commit;
  }
  return { problems, commits: commits.length };
}

export function verifyDirectory(dir, env, { history = false } = {}) {
  const state = readState(dir);
  const result = verifyState(state, { env });
  const out = { problems: [...result.problems], pending: result.pending, notes: result.notes, view: result.view };
  if (history) {
    const h = verifyHistory(dir, env);
    out.problems.push(...h.problems);
    out.commits = h.commits;
  }
  return out;
}

function inferEnv(dir) {
  const state = readState(dir);
  if (!state.jwks) return 'prod';
  try {
    const kids = (JSON.parse(state.jwks.toString('utf8')).keys ?? []).map((k) => String(k.kid));
    return kids.length && kids.every((k) => k.startsWith(ENVIRONMENTS.dev.kidPrefix)) ? 'dev' : 'prod';
  } catch {
    return 'prod';
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dir = resolve(args.dir ?? '.');
  let env = args.env;
  if (env && !Object.hasOwn(ENVIRONMENTS, env)) {
    console.error('--env must be prod or dev');
    process.exitCode = 2;
    return;
  }
  if (!env) {
    env = inferEnv(dir);
    console.log(`(no --env given; judging this as a ${env} log from its key set. Pass --env prod or --env dev to say which.)`);
  }
  const out = verifyDirectory(dir, env, { history: Boolean(args.history) });
  const v = out.view;
  console.log(`log: ${v.headSeq + 1} entries, head seq ${v.headSeq}, ${v.maxSegment + 1} segment(s); ${v.checkpoints.length} checkpoint(s); ${v.keyDoc?.keys.length ?? 0} key(s)`);
  if (args.history) console.log(`history: ${out.commits} commit(s) touching the log checked in order`);
  for (const n of out.notes) console.log(`note: ${n}`);
  for (const p of out.pending) console.log(`pending: ${p}`);
  for (const p of out.problems) console.log(`FAIL: ${p}`);
  console.log(out.problems.length ? `${out.problems.length} check(s) failed` : 'every check holds');
  process.exitCode = out.problems.length ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
