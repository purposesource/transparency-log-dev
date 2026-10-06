#!/usr/bin/env node
// The hourly writer. Reads the log the way the public does (through the edge), checks that it
// only grew, and commits once when something changed. It never pushes: the workflow does that
// with a plain `git push`, and a refused push stops the run red.
//
//   node tools/mirror.mjs --origin https://dev-api.purposesource.org --env dev [--repo .] [--commit] [--dry-run]
//
// The origin and the environment default to the repository variables PSN_ORIGIN and PSN_ENV.
// With --dry-run nothing is written; the run prints what it would commit.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { published, sha256Hex } from './lib/canonical.mjs';
import { evaluate } from './lib/evaluate.mjs';
import { annotate, getPublic, git, gitTry, parseArgs, setOutput, stepSummary } from './lib/runtime.mjs';
import { parseJson } from './lib/schema.mjs';
import { ENVIRONMENTS, MAX_SEGMENT, SERVED_PATHS } from './lib/spec.mjs';
import { readState } from './lib/state.mjs';
import { stamp } from './lib/verify-state.mjs';

/** The most segments one run reads. A log this size is decades away; a document naming more is not believed. */
export const MAX_SEGMENTS_PER_RUN = 5000;

/** Reads the four public files, and every numbered segment latest.json implies (plan correction 3). */
export async function fetchServed(origin, fetchImpl, now = () => new Date()) {
  const base = origin.replace(/\/+$/, '');
  const fetchedAt = now();
  const latest = await getPublic(fetchImpl, `${base}/${SERVED_PATHS.latest}`);
  const segments = new Map();
  if (latest.status === 200) {
    const parsed = parseJson(latest.bytes);
    const n = parsed.value?.segment;
    if (Number.isSafeInteger(n) && n >= 0 && n <= MAX_SEGMENT) {
      if (n >= MAX_SEGMENTS_PER_RUN) {
        return { latest: { status: 0, failure: `latest.json names segment ${n}, more than this mirror reads in one run` }, segments, fetchedAt: iso(fetchedAt) };
      }
      for (let i = 0; i <= n; i++) segments.set(i, await getPublic(fetchImpl, `${base}/${SERVED_PATHS.segment(i)}`));
    }
  }
  const checkpointLatest = latest.status === 404 ? null : await getPublic(fetchImpl, `${base}/${SERVED_PATHS.checkpointLatest}`);
  const jwks = latest.status === 404 ? null : await getPublic(fetchImpl, `${base}/${SERVED_PATHS.jwks}`);
  return { latest, segments, checkpointLatest, jwks, fetchedAt: iso(fetchedAt) };
}

const iso = (d) => d.toISOString().slice(0, 19) + 'Z';

/**
 * The clock the cache windows are measured with (lib/evaluate.mjs): the run's fetch time, and
 * the commit dates of the mirror's own copies, read from git. Git dates are this mirror's own
 * clock, which is the right one here: the question is how long ago THIS mirror saw the longer
 * copy.
 */
export function gitClock(repo, nowMs) {
  const seconds = (out) => (/^[0-9]+$/.test(out) ? Number(out) * 1000 : null);
  const committed = new Map();
  const held = new Map();
  return {
    now: nowMs,
    /** The commit date of the newest commit that wrote `path`, or null when none did. */
    committedAt(path) {
      if (!committed.has(path)) committed.set(path, seconds(gitTry(repo, ['log', '-1', '--format=%ct', '--', path]).out));
      return committed.get(path);
    },
    /**
     * The commit date from which ct/latest.json has named `segment` or a later one: walking
     * back from HEAD, the oldest commit before one that named an earlier segment. Only the
     * commits since the rollover are read, and those latest.json copies are short.
     */
    heldSince(segment) {
      if (held.has(segment)) return held.get(segment);
      let since = null;
      const list = gitTry(repo, ['log', '--format=%H %ct', '--', SERVED_PATHS.latest]).out;
      for (const line of list.split('\n').filter(Boolean)) {
        const [sha, ct] = line.split(' ');
        const blob = gitTry(repo, ['cat-file', 'blob', `${sha}:${SERVED_PATHS.latest}`]);
        if (!blob.ok) break; // the file was removed in that commit
        const m = /"segment":\s*([0-9]+)/.exec(blob.out.slice(0, 400));
        if (!m || Number(m[1]) < segment) break;
        since = seconds(ct);
      }
      held.set(segment, since);
      return since;
    },
  };
}

export function commitMessage(result, origin) {
  const s = result.summary;
  const title = `mirror: head seq ${s.headSeq} in segment ${s.segment}${s.checkpointAsOf ? `, checkpoint ${s.checkpointAsOf}` : ''}`;
  return [
    title,
    '',
    `Head seq: ${s.headSeq}`,
    `Segment: ${s.segment}`,
    `Checkpoint asOf: ${s.checkpointAsOf ?? 'none'}`,
    `latest.json SHA-256: ${s.latestSha256}`,
    `Fetched at: ${s.fetchedAt}`,
    `Origin: ${origin}`,
    `Changed: ${result.changes.join('; ')}`,
    '',
    'Git commit dates are this mirror\'s own clock; only the Software Heritage visit date is independent.',
    '',
  ].join('\n');
}

/**
 * The fingerprint of an incident: the same reasons over the same served documents are one
 * incident. A document's `generatedAt` is left out, so a re-render of the same bad log is not
 * recorded again every hour.
 */
export function incidentFingerprint(result) {
  const stable = (bytes) => {
    const parsed = parseJson(bytes);
    if (parsed.value && typeof parsed.value === 'object' && !Array.isArray(parsed.value) && Object.hasOwn(parsed.value, 'generatedAt')) {
      const { generatedAt, ...rest } = parsed.value;
      return sha256Hex(JSON.stringify(rest));
    }
    return sha256Hex(bytes);
  };
  const files = result.evidence.map((e) => `${e.path}:${stable(e.bytes)}`).sort();
  return sha256Hex(JSON.stringify({ reasons: [...result.incidents].sort(), files }));
}

function knownIncident(repo, fingerprint) {
  const dir = join(repo, 'incidents');
  if (!existsSync(dir)) return null;
  for (const name of readdirSync(dir).sort()) {
    const file = join(dir, name, 'files.json');
    if (!existsSync(file)) continue;
    try {
      if (JSON.parse(readFileSync(file, 'utf8')).fingerprint === fingerprint) return name;
    } catch {
      // an unreadable record is not this incident
    }
  }
  return null;
}

function write(repo, path, bytes) {
  const at = join(repo, path);
  mkdirSync(dirname(at), { recursive: true });
  writeFileSync(at, bytes);
}

/**
 * One run. Returns { outcome, committed, incident, exitCode, result, commitMessage?, incidentRecord? }.
 */
export async function runMirror({
  repo = '.',
  origin,
  env,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  commit = false,
  dryRun = false,
  incidentFile = null,
  log = console.log,
}) {
  const say = (level, msg) => annotate(level, msg, log);
  if (!origin) {
    say('notice', 'PSN_ORIGIN is not set, so the mirror is switched off; nothing was read');
    return { outcome: 'off', committed: false, incident: false, exitCode: 0 };
  }
  if (!/^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?\/?$/.test(origin)) {
    say('error', 'PSN_ORIGIN must be an https origin such as https://dev-api.purposesource.org');
    return { outcome: 'misconfigured', committed: false, incident: false, exitCode: 1 };
  }
  if (!Object.hasOwn(ENVIRONMENTS, env)) {
    say('error', 'PSN_ENV must be prod or dev');
    return { outcome: 'misconfigured', committed: false, incident: false, exitCode: 1 };
  }

  const served = await fetchServed(origin, fetchImpl, now);
  const mirrored = readState(repo);
  const result = evaluate(mirrored, served, { env, clock: gitClock(repo, Date.parse(served.fetchedAt)) });

  for (const n of result.notices) say('notice', n);
  for (const w of result.warnings) say('warning', w);

  const out = { outcome: result.outcome, committed: false, incident: false, exitCode: 0, result };

  if (result.outcome === 'misconfigured') {
    for (const p of result.incidents) say('error', p);
    out.exitCode = 1;
    return out;
  }

  if (result.outcome === 'mirror-broken') {
    for (const p of result.incidents) say('error', `the mirror itself fails: ${p}`);
    say('error', 'the mirror as committed does not verify; nothing was changed and nothing is repaired automatically');
    out.exitCode = 1;
    return out;
  }

  if (result.outcome === 'incident') {
    out.incident = true;
    for (const p of result.incidents) say('error', p);
    const fingerprint = incidentFingerprint(result);
    const folderName = stamp(new Date(served.fetchedAt));
    const known = knownIncident(repo, fingerprint);
    const record = {
      detectedAt: served.fetchedAt,
      origin,
      env,
      fingerprint,
      reasons: result.incidents,
      files: result.evidence.map((e) => ({
        path: e.path,
        url: `${origin.replace(/\/+$/, '')}/${e.path}`,
        sha256: e.sha256,
        kept: e.include,
        withheldBecause: e.include ? null : e.why,
      })),
    };
    out.incidentRecord = { ...record, folder: `incidents/${known ?? folderName}`, repeated: Boolean(known) };
    if (known) {
      say('notice', `the same incident is already recorded in incidents/${known}; not recorded again`);
    } else if (!dryRun) {
      const folder = `incidents/${folderName}`;
      for (const e of result.evidence) if (e.include) write(repo, `${folder}/${e.path}`, e.bytes);
      write(repo, `${folder}/files.json`, published(record));
      const more = result.incidents.length > 1 ? ` (and ${result.incidents.length - 1} more; see files.json)` : '';
      write(repo, `${folder}/reason.txt`, Buffer.from(`${result.incidents[0]}${more}\n`, 'utf8'));
      if (commit) {
        git(repo, ['add', '--', folder]);
        const message = [`incident: the served log failed a check (${folderName})`, '', ...result.incidents.map((p) => `- ${p}`), '', `Origin: ${origin}`, `Fetched at: ${served.fetchedAt}`, `Fingerprint: ${fingerprint}`, ''].join('\n');
        git(repo, ['commit', '-q', '-F', '-'], message);
        out.committed = true;
        out.commitMessage = message;
      }
    }
    if (incidentFile) writeFileSync(incidentFile, JSON.stringify(out.incidentRecord, null, 2));
    return out;
  }

  if (result.outcome === 'changed') {
    out.commitMessage = commitMessage(result, origin);
    if (dryRun) {
      log(`dry run: would write ${[...result.writes.keys()].join(', ')}`);
      log(`dry run: would commit:\n${out.commitMessage}`);
      return out;
    }
    for (const [path, bytes] of result.writes) write(repo, path, bytes);
    if (commit) {
      git(repo, ['add', '--', ...result.writes.keys()]);
      git(repo, ['commit', '-q', '-F', '-'], out.commitMessage);
      out.committed = true;
    }
    say('notice', `mirrored: ${result.changes.join('; ')}`);
    return out;
  }

  if (result.outcome === 'unchanged') say('notice', 'nothing new was published since the last mirrored copy; no commit');
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const repo = resolve(args.repo ?? '.');
  const origin = args.origin ?? process.env.PSN_ORIGIN ?? '';
  const env = args.env ?? process.env.PSN_ENV ?? '';
  const incidentFile = process.env.RUNNER_TEMP ? join(process.env.RUNNER_TEMP, 'incident.json') : null;
  const out = await runMirror({ repo, origin, env, commit: Boolean(args.commit), dryRun: Boolean(args['dry-run']), incidentFile });
  setOutput('outcome', out.outcome);
  setOutput('committed', out.committed);
  setOutput('incident', out.incident);
  const r = out.result;
  stepSummary(
    [
      `### Mirror run: ${out.outcome}`,
      r?.summary ? `Head seq ${r.summary.headSeq} in segment ${r.summary.segment}; newest checkpoint ${r.summary.checkpointAsOf ?? 'none'}; fetched ${r.summary.fetchedAt}.` : '',
      r?.changes?.length ? `Committed: ${r.changes.join('; ')}` : '',
      r?.incidents?.length ? `Incident: ${r.incidents.length} finding(s); see incidents/ and the issue.` : '',
    ].filter(Boolean).join('\n\n'),
  );
  process.exitCode = out.exitCode;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
