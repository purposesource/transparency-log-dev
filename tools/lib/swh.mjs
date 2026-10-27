// The Software Heritage API calls this mirror makes (plan §5). Reads and polls are
// anonymous: Software Heritage serves them to anyone, and a token it refuses must not stop
// them (it answers a token it no longer accepts with 403 AuthenticationFailed
// "invalid_grant", and from 2026-10-08 every run went red at its first read). The account
// token rides on the save request only. If Software Heritage refuses it there as a token
// (401, or a 403 whose exception is AuthenticationFailed), that one request is sent once more
// without it: anonymous save requests are allowed. Any other 403 there (a blocked origin, for
// example) is not about the token and is thrown as it is.
//
// The anonymous budgets, as measured on 2026-10-27: the latest-visit read has its own budget
// of 700 a minute; snapshot reads and save polls share a budget of 120 an hour per IP; the
// anonymous save request's budget was not measured. A run makes about 22 calls an hour, most
// of them the 60-second polls, which fits; a 429 only delays the record.

import { HTTP_TIMEOUT_MS } from './runtime.mjs';

export const SWH_BASE = 'https://archive.softwareheritage.org';

export class SwhError extends Error {
  /**
   * kind: unauthorized (401) | forbidden (403) | rate-limited | unavailable | unexpected.
   * A refusal (401, 403, 429) also carries `exception`, the exception Software Heritage named
   * in its JSON body (AuthenticationFailed for a refused token), or null, and `withToken`,
   * whether the refused call carried the token.
   */
  constructor(kind, message, extra = {}) {
    super(message);
    this.kind = kind;
    Object.assign(this, extra);
  }
}

/** The exception Software Heritage names in a refusal's JSON body, or null. Never more than a name. */
async function exceptionOf(res) {
  try {
    const exception = (await res.json())?.exception;
    return typeof exception === 'string' && /^[A-Za-z][A-Za-z0-9_.]{0,63}$/.test(exception) ? exception : null;
  } catch {
    return null;
  }
}

/** A refusal of the token itself: 401, or a 403 whose exception is AuthenticationFailed. */
const tokenRefused = (err) =>
  err instanceof SwhError && (err.kind === 'unauthorized' || (err.kind === 'forbidden' && err.exception === 'AuthenticationFailed'));

/**
 * `onTokenRefused(err)` is told when Software Heritage refuses the token on a save request,
 * just before that request is sent again without it. It gets the SwhError (its message names
 * the status), never the token.
 */
export function createSwhClient({ token, fetchImpl = globalThis.fetch, base = SWH_BASE, timeoutMs = HTTP_TIMEOUT_MS, onTokenRefused = () => {} }) {
  async function call(method, path, { withToken = false } = {}) {
    let res;
    try {
      res = await fetchImpl(`${base}${path}`, {
        method,
        headers: {
          ...(withToken && token ? { authorization: `Bearer ${token}` } : {}),
          accept: 'application/json',
          'user-agent': 'purposesource-transparency-log-mirror',
        },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new SwhError('unavailable', err?.name === 'TimeoutError' ? `no answer within ${timeoutMs / 1000} s` : 'the request failed');
    }
    const refusal = { withToken: Boolean(withToken && token) };
    if (res.status === 401) throw new SwhError('unauthorized', 'HTTP 401', { ...refusal, exception: await exceptionOf(res) });
    if (res.status === 403) throw new SwhError('forbidden', 'HTTP 403', { ...refusal, exception: await exceptionOf(res) });
    if (res.status === 429) throw new SwhError('rate-limited', 'HTTP 429', { ...refusal, exception: await exceptionOf(res), reset: res.headers.get('x-ratelimit-reset') });
    if (res.status >= 500) throw new SwhError('unavailable', `HTTP ${res.status}`);
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { status: res.status, json };
  }

  return {
    /** The newest visit of the origin that has a snapshot, or null when the origin is not archived. */
    async latestVisit(originUrl) {
      const r = await call('GET', `/api/1/origin/${originUrl}/visit/latest/?require_snapshot=true`);
      if (r.status === 404) return null;
      if (r.status !== 200 || !r.json) throw new SwhError('unexpected', `the latest-visit read was answered HTTP ${r.status}`);
      return r.json;
    },
    /**
     * POST a Save Code Now request for a git origin: the one call that carries the token. A
     * token refused here (401, or 403 AuthenticationFailed) gets the request sent once more,
     * anonymously; any other refusal is thrown as it is.
     */
    async requestSave(originUrl) {
      const path = `/api/1/origin/save/?visit_type=git&origin_url=${encodeURIComponent(originUrl)}`;
      let r;
      try {
        r = await call('POST', path, { withToken: true });
      } catch (err) {
        if (!token || !tokenRefused(err)) throw err;
        onTokenRefused(err);
        r = await call('POST', path);
      }
      if ((r.status !== 200 && r.status !== 201) || !r.json || !Number.isSafeInteger(r.json.id)) {
        throw new SwhError('unexpected', `the save request was answered HTTP ${r.status}`);
      }
      return r.json;
    },
    /** One save request by id, or null when Software Heritage no longer knows it. */
    async getSave(id) {
      const r = await call('GET', `/api/1/origin/save/${id}/`);
      if (r.status === 404) return null;
      if (r.status !== 200 || !r.json) throw new SwhError('unexpected', `the save-request read was answered HTTP ${r.status}`);
      return Array.isArray(r.json) ? (r.json.find((s) => s.id === id) ?? null) : r.json;
    },
    /** The commit `refs/heads/main` points at in a snapshot, or null. */
    async snapshotMain(hex) {
      const r = await call('GET', `/api/1/snapshot/${hex}/?branches_from=refs/heads/main&branches_count=1`);
      if (r.status === 404) return null;
      if (r.status !== 200 || !r.json) throw new SwhError('unexpected', `the snapshot read was answered HTTP ${r.status}`);
      const branch = r.json.branches?.['refs/heads/main'];
      return branch?.target_type === 'revision' && /^[0-9a-f]{40}$/.test(branch.target) ? branch.target : null;
    },
  };
}

export const SNAPSHOT_SWHID = /^swh:1:snp:[0-9a-f]{40}$/;

/** How long a succeeded task may wait for its visit to be linked before it counts as failed. */
export const VISIT_LINK_GRACE_MS = 2 * 60 * 60 * 1000;

/**
 * Where a save request stands: 'done' (succeeded, a full visit, a snapshot id), 'failed',
 * 'rejected' or 'in-flight'. An empty snapshot_swhid is unset (plan correction 14).
 */
export function saveOutcome(save, nowMs) {
  if (!save) return 'failed';
  if (save.save_request_status === 'rejected') return 'rejected';
  if (save.save_task_status === 'failed') return 'failed';
  if (save.save_task_status === 'succeeded') {
    if (save.visit_status === 'full' && typeof save.snapshot_swhid === 'string' && SNAPSHOT_SWHID.test(save.snapshot_swhid)) return 'done';
    if (['partial', 'failed', 'not_found'].includes(save.visit_status)) return 'failed';
    const asked = Date.parse(save.save_request_date ?? '');
    return Number.isFinite(asked) && nowMs - asked > VISIT_LINK_GRACE_MS ? 'failed' : 'in-flight';
  }
  return 'in-flight';
}
