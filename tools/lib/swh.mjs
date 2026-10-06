// The Software Heritage API calls this mirror makes (plan §5). Every call carries the
// account token as a Bearer token, reads and polls included (plan correction 7): GitHub's
// shared runners share the anonymous budget of 120 calls an hour with everyone else, and a
// signed-in user's budget is per user and ten times larger.

import { HTTP_TIMEOUT_MS } from './runtime.mjs';

export const SWH_BASE = 'https://archive.softwareheritage.org';

export class SwhError extends Error {
  /** kind: unauthorized (401) | forbidden (403) | rate-limited | unavailable | unexpected */
  constructor(kind, message, extra = {}) {
    super(message);
    this.kind = kind;
    Object.assign(this, extra);
  }
}

export function createSwhClient({ token, fetchImpl = globalThis.fetch, base = SWH_BASE, timeoutMs = HTTP_TIMEOUT_MS }) {
  async function call(method, path) {
    let res;
    try {
      res = await fetchImpl(`${base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
          'user-agent': 'purposesource-transparency-log-mirror',
        },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new SwhError('unavailable', err?.name === 'TimeoutError' ? `no answer within ${timeoutMs / 1000} s` : 'the request failed');
    }
    if (res.status === 401) throw new SwhError('unauthorized', 'HTTP 401');
    if (res.status === 403) throw new SwhError('forbidden', 'HTTP 403');
    if (res.status === 429) throw new SwhError('rate-limited', 'HTTP 429', { reset: res.headers.get('x-ratelimit-reset') });
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
    /** POST a Save Code Now request for a git origin. */
    async requestSave(originUrl) {
      const r = await call('POST', `/api/1/origin/save/?visit_type=git&origin_url=${encodeURIComponent(originUrl)}`);
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
