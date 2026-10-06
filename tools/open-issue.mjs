#!/usr/bin/env node
// Opens one issue for an incident the mirror recorded, unless an open issue already names the
// same incident (its fingerprint is in the title). Reads $RUNNER_TEMP/incident.json, written by
// tools/mirror.mjs. Uses the job's GITHUB_TOKEN (issues: write); no other credential.

import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { annotate } from './lib/runtime.mjs';

export function issueFor(record, runUrl) {
  const tag = record.fingerprint.slice(0, 12);
  const title = `Incident ${record.folder.replace('incidents/', '')}: the served log failed a check [${tag}]`;
  const body = [
    `The mirror read ${record.origin} at ${record.detectedAt} and the served bytes failed a check. Nothing under ct/, checkpoints/ or jwks.json was changed.`,
    '',
    '**Findings**',
    ...record.reasons.map((r) => `- ${r}`),
    '',
    `**Evidence:** \`${record.folder}/\` (files.json lists each served file with its SHA-256; a file is kept in full only if it passed its schema and the no-names rule).`,
    runUrl ? `**Run:** ${runUrl}` : '',
    '',
    'Compare with the platform\'s own consistency monitor (FS08-114). Do not edit or force-push this repository; history is evidence.',
  ].filter((line) => line !== '').join('\n');
  return { title, body, tag };
}

export async function openIssue({ record, repository, token, api = 'https://api.github.com', fetchImpl = globalThis.fetch, runUrl = null, log = console.log }) {
  const { title, body, tag } = issueFor(record, runUrl);
  const headers = { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'purposesource-transparency-log-mirror' };
  const list = await fetchImpl(`${api}/repos/${repository}/issues?state=open&per_page=100`, { headers, signal: AbortSignal.timeout(30_000) });
  if (list.ok) {
    const open = await list.json();
    if (Array.isArray(open) && open.some((i) => typeof i.title === 'string' && i.title.includes(`[${tag}]`))) {
      annotate('notice', `an open issue already names this incident [${tag}]`, log);
      return { opened: false };
    }
  }
  const res = await fetchImpl(`${api}/repos/${repository}/issues`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ title, body }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    annotate('error', `could not open the incident issue (HTTP ${res.status})`, log);
    return { opened: false, failed: true };
  }
  const issue = await res.json();
  annotate('notice', `opened issue #${issue.number}`, log);
  return { opened: true, number: issue.number };
}

async function main() {
  const file = join(process.env.RUNNER_TEMP ?? '.', 'incident.json');
  if (!existsSync(file)) {
    annotate('warning', 'no incident record was written; no issue opened');
    return;
  }
  const record = JSON.parse(readFileSync(file, 'utf8'));
  const runUrl = process.env.GITHUB_RUN_ID ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : null;
  const out = await openIssue({ record, repository: process.env.GITHUB_REPOSITORY, token: process.env.GITHUB_TOKEN, api: process.env.GITHUB_API_URL ?? 'https://api.github.com', runUrl });
  if (out.failed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
