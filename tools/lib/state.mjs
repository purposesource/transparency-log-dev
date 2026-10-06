// The mirror's files, read from a directory or from a git commit, as raw bytes.
//
// Layout (README, "What this repository holds"):
//   ct/{n}.json                      every numbered segment, as served
//   ct/latest.json                   the open segment, as served
//   ct/checkpoint-latest.json        the newest signed checkpoint artifact, as served
//   checkpoints/{stamp}_{headSeq}.jws       every signed checkpoint ever seen (the compact token, exactly)
//   checkpoints/{stamp}_{headSeq}.swh.json  the Software Heritage snapshot that holds it
//   jwks.json                        the key set, as served

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const SEGMENT_FILE = /^(0|[1-9][0-9]{0,5})\.json$/;
export const CHECKPOINT_FILE = /^([0-9]{8}T[0-9]{6}(?:\.[0-9]{3})?Z_(?:0|[1-9][0-9]*))\.(jws|swh\.json)$/;

export function emptyState() {
  return {
    segments: new Map(),
    latest: null,
    checkpointLatest: null,
    checkpoints: new Map(),
    swhRecords: new Map(),
    jwks: null,
    strays: [],
  };
}

export function cloneState(state) {
  return {
    segments: new Map(state.segments),
    latest: state.latest,
    checkpointLatest: state.checkpointLatest,
    checkpoints: new Map(state.checkpoints),
    swhRecords: new Map(state.swhRecords),
    jwks: state.jwks,
    strays: [...state.strays],
  };
}

/** Puts one file of the layout into `state`; anything else under ct/ or checkpoints/ is a stray. */
function place(state, path, bytes) {
  if (path === 'jwks.json') state.jwks = bytes;
  else if (path === 'ct/latest.json') state.latest = bytes;
  else if (path === 'ct/checkpoint-latest.json') state.checkpointLatest = bytes;
  else if (path.startsWith('ct/') && SEGMENT_FILE.test(path.slice(3))) state.segments.set(Number(SEGMENT_FILE.exec(path.slice(3))[1]), bytes);
  else if (path.startsWith('checkpoints/') && CHECKPOINT_FILE.test(path.slice(12))) {
    const [, name, ext] = CHECKPOINT_FILE.exec(path.slice(12));
    (ext === 'jws' ? state.checkpoints : state.swhRecords).set(name, bytes);
  } else if (path.startsWith('ct/') || path.startsWith('checkpoints/')) state.strays.push(path);
}

/** A state from a map of layout paths to bytes (tests, and anything that holds files in memory). */
export function stateFromFiles(files) {
  const state = emptyState();
  for (const [path, bytes] of Object.entries(files)) place(state, path, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
  return state;
}

/** The mirror's state as it stands in a working tree. */
export function readState(dir) {
  const state = emptyState();
  if (existsSync(join(dir, 'jwks.json'))) place(state, 'jwks.json', readFileSync(join(dir, 'jwks.json')));
  for (const sub of ['ct', 'checkpoints']) {
    const at = join(dir, sub);
    if (!existsSync(at)) continue;
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      if (entry.isFile()) place(state, `${sub}/${entry.name}`, readFileSync(join(at, entry.name)));
      else state.strays.push(`${sub}/${entry.name}/`);
    }
  }
  return state;
}

/** The mirror's state as it stood at a commit. */
export function readStateAt(dir, commit) {
  const state = emptyState();
  const listing = execFileSync('git', ['ls-tree', '-r', '-z', '--name-only', commit, '--', 'jwks.json', 'ct', 'checkpoints'], { cwd: dir });
  for (const path of listing.toString('utf8').split('\0').filter(Boolean)) {
    place(state, path, execFileSync('git', ['cat-file', 'blob', `${commit}:${path}`], { cwd: dir, maxBuffer: 64 * 1024 * 1024 }));
  }
  return state;
}

/** A path safe to print: plain characters only. */
export function safePath(path) {
  return /^[A-Za-z0-9._/-]{1,120}$/.test(path) ? path : 'a file with an unusual name';
}
