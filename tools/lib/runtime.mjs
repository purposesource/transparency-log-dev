// Small runtime helpers: HTTP reads with a bound, GitHub Actions annotations and outputs, git.

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

/** The bound on every HTTP call (plan §5: 30 seconds). */
export const HTTP_TIMEOUT_MS = 30_000;

/** The largest body read: a closed segment is about two megabytes. */
const MAX_BODY = 32 * 1024 * 1024;

/**
 * GET one public file as the public reads it: no credential, no redirect followed, no
 * cache-busting query. Returns { status, bytes? , failure? }; status 0 means no answer.
 */
export async function getPublic(fetchImpl, url, timeoutMs = HTTP_TIMEOUT_MS) {
  try {
    const res = await fetchImpl(url, {
      headers: { accept: 'application/json', 'user-agent': 'purposesource-transparency-log-mirror' },
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status !== 200) {
      await res.body?.cancel?.().catch(() => {});
      return { status: res.status };
    }
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length > MAX_BODY) return { status: 0, failure: 'the body is larger than any segment can be' };
    return { status: 200, bytes };
  } catch (err) {
    return { status: 0, failure: err?.name === 'TimeoutError' ? `no answer within ${timeoutMs / 1000} s` : 'the request failed' };
  }
}

/** GitHub's escaping for workflow-command data. */
const escapeData = (s) => String(s).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');

export function annotate(level, message, log = console.log) {
  log(`::${level}::${escapeData(message)}`);
}

export function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${String(value).replaceAll('\n', ' ')}\n`);
}

export function stepSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`);
}

/** git in `cwd`; returns trimmed stdout. */
export function git(cwd, args, input) {
  return execFileSync('git', args, { cwd, input, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
}

/** git that may fail: returns { ok, out }. */
export function gitTry(cwd, args) {
  try {
    return { ok: true, out: execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() };
  } catch {
    return { ok: false, out: '' };
  }
}

/** Parses `--name value` and `--flag` arguments. */
export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}
