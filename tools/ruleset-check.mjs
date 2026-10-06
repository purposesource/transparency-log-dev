#!/usr/bin/env node
// Checks that `main` is protected the way the plan asks (§4, operator act B): a ruleset that
// blocks force pushes (`non_fast_forward`) and deletion. Reads GitHub's "rules for a branch"
// answer with the job's GITHUB_TOKEN. The bypass list is not visible to that token; the
// operator sets it to empty when creating the ruleset.
//
// Prod: a missing rule turns the run red (after the mirror's own commit has landed).
// Dev: a warning, so the practice repository works before the ruleset exists.

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { annotate } from './lib/runtime.mjs';

export const REQUIRED_RULES = ['non_fast_forward', 'deletion'];

export async function checkRuleset({ repository, token, env, api = 'https://api.github.com', fetchImpl = globalThis.fetch, log = console.log }) {
  const res = await fetchImpl(`${api}/repos/${repository}/rules/branches/main`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'purposesource-transparency-log-mirror' },
    signal: AbortSignal.timeout(30_000),
  });
  const level = env === 'prod' ? 'error' : 'warning';
  if (!res.ok) {
    annotate('warning', `could not read the rules for main (HTTP ${res.status}); not checked this run`, log);
    return { ok: true, checked: false };
  }
  const rules = await res.json();
  const types = new Set(Array.isArray(rules) ? rules.map((r) => r?.type) : []);
  const missing = REQUIRED_RULES.filter((t) => !types.has(t));
  if (missing.length) {
    annotate(level, `main is not protected by a ruleset rule for: ${missing.join(', ')}. Add a ruleset on main that blocks force pushes and deletion, with nobody exempt.`, log);
    return { ok: env !== 'prod', checked: true, missing };
  }
  annotate('notice', 'main is protected against force pushes and deletion', log);
  return { ok: true, checked: true, missing: [] };
}

async function main() {
  const out = await checkRuleset({
    repository: process.env.GITHUB_REPOSITORY,
    token: process.env.GITHUB_TOKEN,
    env: process.env.PSN_ENV,
    api: process.env.GITHUB_API_URL ?? 'https://api.github.com',
  });
  if (!out.ok) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
