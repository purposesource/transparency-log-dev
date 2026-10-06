#!/usr/bin/env node
// The Software Heritage loop (plan §5 with corrections 7 and 14). Asks Software Heritage to
// save this repository after the mirror committed, polls the request, and writes
// checkpoints/{name}.swh.json beside every checkpoint the archived snapshot holds.
//
//   SWH_TOKEN=… ORIGIN_URL=https://github.com/purposesource/transparency-log PSN_ENV=prod node tools/archive.mjs [--repo .] [--commit]
//
// THE RULES
//   - What needs archiving is the newest commit that touched ct/, checkpoints/, jwks.json or
//     incidents/ (the "target"). Commits that only move swh/state.json never need a save.
//   - Covered = a FULL visit's snapshot whose refs/heads/main is the target or a descendant.
//   - At most ONE new save request per run. A request that fails, or that succeeds without
//     capturing the target (a race: Software Heritage hands back a request already
//     scheduled), gets its one new request on the run that sees it.
//   - Poll every 60 s for up to 20 minutes, then stop; a request still in flight is kept in
//     swh/state.json and polled by id on the next run (never by listing every request).
//   - Loop guard: a commit that adds a record is a new target, so it gets exactly one more
//     save; that save adds no record, so the loop stops.
//   - The 24-hour clock starts when this job FIRST ASKS Software Heritage for the target (the
//     first save request, or the first attempt that found Software Heritage unreachable), and
//     is kept as `requestedAt` in swh/state.json across runs. A failed request keeps the clock
//     running; a save that completed without capturing the newest target restarts it (Software
//     Heritage works, the log just moved on). Red when no full snapshot covers the target 24
//     hours after that first ask. A token that arrives late therefore starts the clock then,
//     not at the commit's date.
//   - 429: stop, try again next run. 401: red, the token expired or was revoked. 403: red,
//     forbidden (the token lacks permission). Red too when the snapshot's main is not in this
//     repository's history (history was rewritten: repair nothing).
//   - No token: the mirror's commits still land and this part is skipped. On dev that is a
//     notice. On prod it is a warning on every run, and red once the first log commit is more
//     than 24 hours old.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { published } from './lib/canonical.mjs';
import { annotate, git, gitTry, parseArgs, setOutput, stepSummary } from './lib/runtime.mjs';
import { isDateTime } from './lib/schema.mjs';
import { createSwhClient, saveOutcome, SNAPSHOT_SWHID, SwhError } from './lib/swh.mjs';
import { CHECKPOINT_FILE } from './lib/state.mjs';

export const STATE_FILE = 'swh/state.json';
export const ARCHIVED_PATHS = ['ct', 'checkpoints', 'jwks.json', 'incidents'];
export const POLL_INTERVAL_MS = 60_000;
export const POLL_BUDGET_MS = 20 * 60_000;
export const STALE_AFTER_MS = 24 * 60 * 60_000;

class Diverged extends Error {}

const iso = (ms) => new Date(ms).toISOString().slice(0, 19) + 'Z';

/**
 * swh/state.json's `pending`: { saveRequestId, target, requestedAt }. `saveRequestId` is the
 * request in flight, or null when none is (the last one failed, or Software Heritage could
 * not be reached); `requestedAt` is when this job first asked for the target, the start of
 * the 24-hour clock.
 */
function readPending(repo) {
  const file = join(repo, STATE_FILE);
  if (!existsSync(file)) return null;
  try {
    const p = JSON.parse(readFileSync(file, 'utf8')).pending;
    if (!p || !/^[0-9a-f]{40}$/.test(p.target) || !(p.saveRequestId === null || Number.isSafeInteger(p.saveRequestId))) return null;
    return { saveRequestId: p.saveRequestId, target: p.target, requestedAt: isDateTime(p.requestedAt) ? p.requestedAt : null };
  } catch {
    return null;
  }
}

/** The commit date of the first commit that touched the log, or null. */
function firstLogCommitAt(repo) {
  const first = gitTry(repo, ['log', '--reverse', '--format=%ct', '--', ...ARCHIVED_PATHS]).out.split('\n')[0];
  return /^[0-9]+$/.test(first ?? '') ? Number(first) * 1000 : null;
}

export async function runArchive({
  repo = '.',
  originUrl,
  token,
  env = 'dev',
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  pollIntervalMs = POLL_INTERVAL_MS,
  pollBudgetMs = POLL_BUDGET_MS,
  commit = false,
  log = console.log,
}) {
  const say = (level, msg) => annotate(level, msg, log);
  const out = { status: 'skipped', committed: false, red: false, records: [], requests: 0 };

  if (!token) {
    out.status = 'no-token';
    const first = env === 'prod' ? firstLogCommitAt(repo) : null;
    if (first === null) {
      say('notice', 'SWH_TOKEN is not set: the Software Heritage save is skipped and stays pending; the mirror\'s commits are unaffected');
      return out;
    }
    const due = first + STALE_AFTER_MS;
    if (now() > due) {
      say('error', `SWH_TOKEN is not set, and the first log commit (${iso(first)}) is more than 24 hours old: Software Heritage is not archiving this repository. Store the token as the environment secret SWH_TOKEN of the environment "archive".`);
      out.red = true;
    } else {
      say('warning', `SWH_TOKEN is not set: Software Heritage is not asked to archive this repository. If it is still missing at ${iso(due)} (24 hours after the first log commit), the run turns red.`);
    }
    return out;
  }
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(originUrl ?? '')) {
    say('error', 'ORIGIN_URL must be this repository\'s https://github.com/{owner}/{name} URL');
    out.red = true;
    return out;
  }

  const target = gitTry(repo, ['log', '-1', '--format=%H', '--', ...ARCHIVED_PATHS]).out;
  if (!target) {
    say('notice', 'nothing to archive yet: no log, checkpoint, key-set or incident file has been committed');
    return out;
  }
  const head = git(repo, ['rev-parse', 'HEAD']);
  const client = createSwhClient({ token, fetchImpl });
  const committedPending = readPending(repo);
  let pending = committedPending;
  let covered = false;
  let snapshotUsed = null;
  // The 24-hour clock (see THE RULES): when this job first asked for the target.
  let since = committedPending?.requestedAt ? Date.parse(committedPending.requestedAt) : null;
  const waiting = () => ({ saveRequestId: null, target: pending?.target ?? target, requestedAt: iso(since ?? now()) });

  const known = (sha) => gitTry(repo, ['cat-file', '-e', `${sha}^{commit}`]).ok;
  const ancestor = (a, b) => a === b || gitTry(repo, ['merge-base', '--is-ancestor', a, b]).ok;
  const checkHistory = (main) => {
    if (!known(main) || !ancestor(main, head)) {
      throw new Diverged(
        `the commit Software Heritage archived as main, ${main}, is not in this repository's history: the history was rewritten. ` +
          'Repair nothing and never force-push; the next commit records it under incidents/ and names the last snapshot that holds the true history.',
      );
    }
  };
  const writeRecords = (main, info) => {
    // A record that would not verify is never written: the next mirror run checks the whole
    // repository first, and a malformed record would stop it.
    if (!isDateTime(info.visit_date) || !SNAPSHOT_SWHID.test(info.snapshot_swhid ?? '') || info.visit_status !== 'full') {
      say('notice', 'the snapshot is not described completely yet (visit date, status or id missing); its records wait for the next run');
      return;
    }
    const listing = git(repo, ['ls-tree', '--name-only', main, 'checkpoints/']);
    for (const path of listing.split('\n').filter(Boolean)) {
      const m = CHECKPOINT_FILE.exec(path.slice('checkpoints/'.length));
      if (!m || m[2] !== 'jws') continue;
      const file = `checkpoints/${m[1]}.swh.json`;
      if (existsSync(join(repo, file)) || out.records.some((r) => r.file === file)) continue;
      const record = {
        checkpoint: `checkpoints/${m[1]}.jws`,
        origin_url: originUrl,
        snapshot_swhid: info.snapshot_swhid,
        visit_date: info.visit_date,
        visit_status: info.visit_status,
        save_request_id: info.save_request_id,
        save_request_url: info.save_request_id === null ? null : `https://archive.softwareheritage.org/api/1/origin/save/${info.save_request_id}/`,
        mirror_commit: main,
      };
      mkdirSync(dirname(join(repo, file)), { recursive: true });
      writeFileSync(join(repo, file), published(record));
      out.records.push({ file, record });
    }
  };

  try {
    let save = pending?.saveRequestId != null ? await client.getSave(pending.saveRequestId) : null;
    if (pending && !save) pending = waiting(); // no request in flight (or one Software Heritage forgot); the clock runs on

    // Covered already? Any full visit counts: one made by our request, by the optional
    // webhook, by Software Heritage's own revisits, or by a request whose id was lost.
    if (!(save && saveOutcome(save, now()) === 'done')) {
      const visit = await client.latestVisit(originUrl);
      if (visit?.status === 'full' && /^[0-9a-f]{40}$/.test(visit.snapshot ?? '')) {
        const main = await client.snapshotMain(visit.snapshot);
        if (main) {
          checkHistory(main);
          const swhid = `swh:1:snp:${visit.snapshot}`;
          const ours = save && save.snapshot_swhid === swhid ? save.id : null;
          writeRecords(main, { snapshot_swhid: swhid, visit_date: visit.date, visit_status: 'full', save_request_id: ours });
          if (ancestor(target, main)) {
            covered = true;
            snapshotUsed = swhid;
            pending = null;
          }
        }
      }
    }

    const deadline = now() + pollBudgetMs;
    while (!covered) {
      if (!save) {
        if (out.requests >= 1) {
          say('notice', 'one save request per run has been made; the next run asks again');
          break;
        }
        save = await client.requestSave(originUrl);
        out.requests++;
        if (since === null) since = now();
        pending = { saveRequestId: save.id, target, requestedAt: iso(since) };
        say('notice', `asked Software Heritage to save ${originUrl} (save request ${save.id}) for ${target}`);
      }
      const state = saveOutcome(save, now());
      if (state === 'rejected') {
        say('error', `Software Heritage rejected save request ${save.id}; GitHub repositories are normally accepted without moderation, so check the origin URL`);
        out.red = true;
        pending = null;
        break;
      }
      if (state === 'done') {
        const main = await client.snapshotMain(save.snapshot_swhid.slice('swh:1:snp:'.length));
        if (main) {
          checkHistory(main);
          writeRecords(main, { snapshot_swhid: save.snapshot_swhid, visit_date: save.visit_date, visit_status: save.visit_status, save_request_id: save.id });
          if (ancestor(target, main)) {
            covered = true;
            snapshotUsed = save.snapshot_swhid;
            pending = null;
            break;
          }
        }
        say('notice', `save request ${save.id} finished without capturing ${target}; one new request`);
        save = null;
        pending = null;
        since = null; // a save completed, so Software Heritage works: the clock restarts with the next request
        continue;
      }
      if (state === 'failed') {
        say('notice', `save request ${save.id} ended without a full visit; one new request`);
        save = null;
        pending = { saveRequestId: null, target, requestedAt: iso(since ?? now()) };
        continue;
      }
      if (now() + pollIntervalMs > deadline) {
        say('notice', `save request ${save.id} is still in flight after ${pollBudgetMs / 60000} minutes; the next run polls it again`);
        break;
      }
      await sleep(pollIntervalMs);
      save = await client.getSave(save.id);
      if (!save) pending = waiting();
    }
  } catch (err) {
    if (err instanceof Diverged) {
      say('error', err.message);
      out.red = true;
      out.status = 'diverged';
    } else if (err instanceof SwhError && err.kind === 'unauthorized') {
      say('error', `Software Heritage refused the token (${err.message}): it has expired or was revoked. Make a new token on the Software Heritage account page and store it as the environment secret SWH_TOKEN of the environment "archive".`);
      out.red = true;
      out.status = 'unauthorized';
    } else if (err instanceof SwhError && err.kind === 'forbidden') {
      say('error', `Software Heritage answered ${err.message}: forbidden (token lacks permission) for this call, or the origin is refused. Check the token's account and the origin URL; this does not mean the token expired.`);
      out.red = true;
      out.status = 'forbidden';
    } else if (err instanceof SwhError && err.kind === 'rate-limited') {
      const reset = Number(err.reset);
      say('notice', `Software Heritage answered 429 (rate limited${Number.isFinite(reset) && reset > 0 ? `, the budget resets at ${iso(reset * 1000)}` : ''}); stopping, the next run tries again`);
      out.status = 'rate-limited';
    } else if (err instanceof SwhError) {
      say('warning', `Software Heritage did not answer as expected (${err.message}); the next run tries again`);
      out.status = 'unavailable';
    } else {
      throw err;
    }
  }

  // Not covered and nothing in flight: remember when this job first asked, so the 24-hour
  // clock survives the runs (an outage before any request counts too).
  if (!covered && !out.red && pending === null) pending = waiting();

  // What this run leaves behind: records, and a request that outlives the run.
  const pendingChanged = JSON.stringify(pending ?? null) !== JSON.stringify(committedPending ?? null);
  if (pendingChanged) {
    mkdirSync(join(repo, 'swh'), { recursive: true });
    writeFileSync(join(repo, STATE_FILE), published({ pending: pending ?? null }));
  }
  if (commit && (out.records.length || pendingChanged)) {
    const paths = [...out.records.map((r) => r.file), ...(pendingChanged ? [STATE_FILE] : [])];
    git(repo, ['add', '--', ...paths]);
    const first = out.records[0]?.record;
    const title = first
      ? `archive: Software Heritage snapshot ${first.snapshot_swhid} holds ${first.mirror_commit.slice(0, 12)}`
      : pending?.saveRequestId != null
        ? `archive: save request ${pending.saveRequestId} for ${pending.target.slice(0, 12)} is in flight`
        : pending
          ? `archive: no save request in flight; first asked for ${pending.target.slice(0, 12)} at ${pending.requestedAt}`
          : 'archive: no save request in flight';
    const body = out.records.map((r) => `Record: ${r.file} (visit ${r.record.visit_date}, save request ${r.record.save_request_id ?? 'none'})`);
    git(repo, ['commit', '-q', '-F', '-'], [title, '', ...body, ''].join('\n'));
    out.committed = true;
  }

  if (covered) {
    out.status = 'covered';
    say('notice', `a full Software Heritage snapshot (${snapshotUsed}) holds ${target}`);
  } else if (!out.red) {
    const firstAsked = Date.parse(pending.requestedAt);
    if (now() - firstAsked > STALE_AFTER_MS) {
      say('error', `no full Software Heritage snapshot holds ${target} 24 hours after this job first asked for it (${pending.requestedAt})`);
      out.red = true;
      out.status = 'stale';
    } else if (out.status === 'skipped') out.status = 'pending';
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const out = await runArchive({
    repo: resolve(args.repo ?? '.'),
    originUrl: process.env.ORIGIN_URL,
    token: process.env.SWH_TOKEN,
    env: process.env.PSN_ENV,
    commit: Boolean(args.commit),
  });
  setOutput('committed', out.committed);
  setOutput('red', out.red);
  stepSummary(`### Software Heritage: ${out.status}${out.records.length ? `\n\nRecords: ${out.records.map((r) => r.file).join(', ')}` : ''}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
