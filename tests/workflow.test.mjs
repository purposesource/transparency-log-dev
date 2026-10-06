// The workflow's hygiene, read from the file itself (no YAML library: line rules).

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { HERE } from './helpers.mjs';

const ROOT = join(HERE, '..');
const yml = readFileSync(join(ROOT, '.github/workflows/mirror.yml'), 'utf8');
const lines = yml.split('\n');

/** The lines of every `run:` script (inline or block). */
function runScripts() {
  const scripts = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)(- )?run: ?(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (m[3] && m[3] !== '|') {
      scripts.push(m[3]);
      continue;
    }
    const indent = m[1].length + (m[2] ? 2 : 0);
    const body = [];
    for (let j = i + 1; j < lines.length && (lines[j].trim() === '' || lines[j].search(/\S/) > indent); j++) body.push(lines[j]);
    scripts.push(body.join('\n'));
  }
  return scripts;
}

test('every action is pinned to a full commit SHA, with its tag in a comment', () => {
  const uses = lines.filter((l) => /^\s*(- )?uses:/.test(l));
  assert.ok(uses.length >= 4);
  for (const l of uses) assert.match(l, /uses: [\w.-]+\/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/, l);
});

test('checkout takes the whole history (the ancestry check needs it) and Node 22', () => {
  assert.equal((yml.match(/fetch-depth: 0/g) ?? []).length, 2);
  assert.equal((yml.match(/node-version: 22/g) ?? []).length, 2);
});

test('permissions are contents: write and issues: write, nothing else', () => {
  const start = lines.indexOf('permissions:');
  assert.ok(start >= 0);
  const block = [];
  for (let i = start + 1; i < lines.length && lines[i].startsWith('  '); i++) block.push(lines[i].trim());
  assert.deepEqual(block, ['contents: write', 'issues: write']);
  assert.equal((yml.match(/^\s*permissions:/gm) ?? []).length, 1, 'no job widens them');
});

test('the schedule is :37 every hour, off the top of the hour, plus manual runs', () => {
  assert.match(yml, /- cron: "37 \* \* \* \*"/);
  assert.match(yml, /^\s+workflow_dispatch:$/m);
});

test('one run at a time, and a running one is never cancelled', () => {
  assert.match(yml, /concurrency:\n\s+group: [\w-]+\n\s+cancel-in-progress: false/);
});

test('no ${{ }} expression inside a run script', () => {
  for (const script of runScripts()) assert.ok(!script.includes('${{'), script);
});

test('pushes are plain: no force, no --force-with-lease, no +refspec', () => {
  for (const script of runScripts()) {
    if (!script.includes('git push')) continue;
    assert.doesNotMatch(script, /--force|-f\b|\+HEAD|\+refs/);
  }
});

test('SWH_TOKEN appears once, in the archive job, which alone uses the "archive" environment', () => {
  assert.equal((yml.match(/SWH_TOKEN: \$\{\{ secrets\.SWH_TOKEN \}\}/g) ?? []).length, 1);
  assert.equal((yml.match(/^\s+environment: archive$/gm) ?? []).length, 1);
  const archiveJob = yml.slice(yml.indexOf('\n  archive:'));
  assert.match(archiveJob, /environment: archive/);
  assert.match(archiveJob, /secrets\.SWH_TOKEN/);
  assert.ok(!yml.slice(0, yml.indexOf('\n  archive:')).includes('secrets.'), 'the mirror job sees no secret');
});

test('the repository holds no npm dependency: no package.json at the root, no node_modules, no lock file', () => {
  const root = readdirSync(ROOT);
  for (const f of ['package.json', 'package-lock.json', 'node_modules', 'yarn.lock', 'pnpm-lock.yaml']) assert.ok(!root.includes(f), f);
  const tools = readdirSync(join(ROOT, 'tools'), { recursive: true }).map(String).filter((f) => f.endsWith('.mjs'));
  for (const f of tools) {
    const src = readFileSync(join(ROOT, 'tools', f), 'utf8');
    for (const m of src.matchAll(/^import .* from '([^']+)';$/gm)) assert.ok(m[1].startsWith('node:') || m[1].startsWith('./') || m[1].startsWith('../'), `${f} imports ${m[1]}`);
  }
});

test('every text file is LF only', () => {
  const walk = (dir) =>
    readdirSync(dir).flatMap((f) => {
      if (f === '.git') return [];
      const p = join(dir, f);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
  for (const file of walk(ROOT)) assert.ok(!readFileSync(file).includes(0x0d), `${file} has a CR`);
});
