// The workflow's hygiene, read from the file itself (no YAML library: line rules).

import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { test } from 'node:test';

import { HERE } from './helpers.mjs';

const ROOT = join(HERE, '..');
const yml = readFileSync(join(ROOT, '.github/workflows/mirror.yml'), 'utf8');
const lines = yml.split('\n');

/** One job's block: from `  {name}:` to the next job or the end. */
function jobBlock(name) {
  const start = yml.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0, `job ${name}`);
  const rest = yml.slice(start + 1);
  const end = rest.slice(1).search(/\n  [A-Za-z0-9_-]+:\n/);
  return end < 0 ? rest : rest.slice(0, end + 2);
}

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

test('the actions are node24 releases: checkout v7.0.1 and setup-node v7.0.0 (both action.yml files say `using: node24`)', () => {
  const uses = lines.filter((l) => /^\s*(- )?uses:/.test(l)).map((l) => l.trim().replace(/^- /, ''));
  assert.equal(uses.length, 4);
  for (const l of uses) {
    assert.ok(
      ['uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1', 'uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0'].includes(l),
      l,
    );
  }
});

test('checkout takes the whole history (the ancestry check needs it) and Node 22', () => {
  assert.equal((yml.match(/fetch-depth: 0/g) ?? []).length, 2);
  assert.equal((yml.match(/node-version: 22/g) ?? []).length, 2);
});

test('permissions: none for the workflow; the mirror job writes contents and issues, the archive job contents only', () => {
  assert.ok(lines.includes('permissions: {}'), 'the workflow-level block grants nothing');
  const granted = (job) => {
    const m = /\n    permissions:\n((?:      [a-z-]+: [a-z]+\n)+)/.exec(jobBlock(job));
    assert.ok(m, `${job} declares its permissions`);
    return m[1].trim().split('\n').map((l) => l.trim());
  };
  assert.deepEqual(granted('mirror'), ['contents: write', 'issues: write']);
  assert.deepEqual(granted('archive'), ['contents: write']);
  assert.equal((yml.match(/^\s*permissions:/gm) ?? []).length, 3, 'one block for the workflow and one per job, nothing else');
});

test('an unset PSN_ORIGIN skips both jobs (the workflow stays green and does nothing)', () => {
  for (const job of ['mirror', 'archive']) {
    const m = /\n    if: (.+)\n/.exec(jobBlock(job));
    assert.ok(m, `${job} has a job-level if`);
    assert.ok(m[1].includes("vars.PSN_ORIGIN != ''"), `${job}: ${m[1]}`);
    assert.ok(m[1].includes("github.ref == 'refs/heads/main'"), `${job}: ${m[1]}`);
  }
});

test('the self-test runs every test file by glob, which works on every Node version, and README names the same command', () => {
  assert.match(yml, /^\s+run: node --test tests\/\*\.test\.mjs$/m);
  assert.ok(readFileSync(join(ROOT, 'README.md'), 'utf8').includes('node --test tests/*.test.mjs'));
  assert.ok(!existsSync(join(ROOT, 'tests', 'package.json')), 'no package main is needed to find the tests');
});

test('the archive job knows the environment (the missing-token rule differs on prod)', () => {
  assert.match(jobBlock('archive'), /PSN_ENV: \$\{\{ vars\.PSN_ENV \}\}/);
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

/**
 * What the self-test holds to LF: the code, its tests and the docs. Never incidents/: evidence
 * is kept exactly as served, so a served file with CR line ends becomes an incident whose
 * evidence keeps its CRs; and never the mirrored files, which are checked by the verifier.
 */
const SELF_TEST_PATHS = ['tools', 'tests', '.github', 'README.md', '.gitattributes'];

function filesWithCr(root) {
  const walk = (p) => (statSync(p).isDirectory() ? readdirSync(p).flatMap((f) => walk(join(p, f))) : [p]);
  return SELF_TEST_PATHS.filter((p) => existsSync(join(root, p)))
    .flatMap((p) => walk(join(root, p)))
    .filter((f) => readFileSync(f).includes(0x0d))
    .map((f) => relative(root, f));
}

test('the code, its tests and the docs are LF only', () => {
  assert.deepEqual(filesWithCr(ROOT), []);
});

test('the LF self-test leaves incidents/ and the mirrored files alone: a CRLF incident cannot stop the mirror', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ctmirror-lf-'));
  mkdirSync(join(dir, 'incidents', '20261006T103700Z', 'ct'), { recursive: true });
  writeFileSync(join(dir, 'incidents', '20261006T103700Z', 'ct', 'latest.json'), '{\r\n  "segment": 0\r\n}\r\n');
  writeFileSync(join(dir, 'jwks.json'), '{\r\n}\r\n');
  mkdirSync(join(dir, 'tools'));
  writeFileSync(join(dir, 'tools', 'a.mjs'), 'export {};\n');
  assert.deepEqual(filesWithCr(dir), []);
  writeFileSync(join(dir, 'tools', 'b.mjs'), 'export {};\r\n');
  assert.deepEqual(filesWithCr(dir), [join('tools', 'b.mjs')]);
});
