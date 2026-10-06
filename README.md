# Purpose Source transparency log: public mirror

This repository is a copy of the Purpose Source certificate transparency log, as the public edge
at `https://api.purposesource.org` serves it. A GitHub Actions workflow in this repository reads
the log every hour, checks that the log only grew, and commits once when something new was
published. After each change it asks [Software Heritage](https://www.softwareheritage.org/) to
archive the repository. Software Heritage is a non-profit archive of public code, and its copy
is the part that neither the Association nor GitHub controls.

**What it holds is hashes, types and times only.** A log entry carries a SHA-256 hash, a type
code, a kind, a reference to another entry's hash and a timestamp. It carries nothing else: no
name, no email address, nothing about a person (CERT-031). Waivers, certificates and the publish
log are not copied here.

## What this repository holds

| Path | What it is |
|---|---|
| `ct/{n}.json` | Every numbered segment of the log, byte for byte as served at `/ct/{n}.json`. A closed segment holds 10,000 entries and never changes; the open one grows. |
| `ct/latest.json` | The open segment, as served at `/ct/latest.json`. |
| `ct/checkpoint-latest.json` | The newest signed checkpoint, as served at `/ct/checkpoint-latest.json`. |
| `checkpoints/{YYYYMMDDTHHMMSSZ}_{headSeq}.jws` | Every signed checkpoint the mirror has seen, written once and never changed. The file is the compact token exactly, with no trailing newline, so its SHA-256 is the token's SHA-256. The edge serves only the newest checkpoint, so this folder is the only public place where the older ones stay. |
| `checkpoints/{…}.swh.json` | The Software Heritage snapshot that holds that checkpoint (see below). |
| `jwks.json` | The key set, as served at `/jwks.json`. |
| `incidents/{YYYYMMDDTHHMMSSZ}/` | Evidence of a served log that failed a check (see below). Empty while all is well. |
| `swh/state.json` | A Software Heritage save request that was still running when a run ended, and when the workflow first asked Software Heritage for the newest commit (the start of the 24-hour rule below). Not evidence; it only lets the next run continue. |
| `tools/`, `tests/`, `.github/workflows/mirror.yml` | The verifier, its tests, and the workflow that writes this repository. |

File names carry no colon, so the repository can be cloned on Windows. `.gitattributes` says
`* -text`, so git never rewrites line endings: every hash is over the exact bytes served.

## The clocks

**Git commit dates are this mirror's own clock.** They are written by the workflow and prove
nothing about time. **The independent clock is Software Heritage's `visit_date`**: the moment
Software Heritage fetched this repository, recorded in its archive and copied into each
`.swh.json` file.

## Verify it yourself

You need git and Node.js 22 or later. Nothing is installed: the tools use only Node.js's own
modules.

```sh
git clone https://github.com/purposesource/transparency-log
cd transparency-log
node tools/verify.mjs --env prod             # the files as they stand
node tools/verify.mjs --env prod --history   # and every commit against the one before it
node --test tests/*.test.mjs                 # the verifier's own tests
```

`verify.mjs` prints `every check holds` and exits 0, or prints each failure and exits 1. A line
marked `pending` is a check that cannot run yet because a copy is still short. The edge caches a
numbered segment for up to a day, so a segment that just closed may still be served short for
that long. Pending is not a failure; it is checked again on every run.

### What the verifier checks

Each file on its own:

- **The segments** follow `ct-segment.v1` (specification 1.3.0). The required members are
  present and nothing else is. Each `seq` runs on from `startSeq`, and `startSeq` is the
  segment number times 10,000. `h` and `ref` are 64 lowercase hex characters. `typ` is one the
  specification lists. `ts` is an RFC 3339 date-time. An `issue` entry's `ref` is null. A
  `revoke`, `status` or `record` entry names another entry in `ref`, and its `h` is the
  SHA-256 of its own members `{kind, ref, ts, typ}` in RFC 8785 form, as the specification
  defines it.
- **The checkpoint artifact** follows the `CtCheckpointArtifact` component of
  `edge-public.v1`. Its token follows `ct-checkpoint.v1` (specification 1.0.0). The convenience
  payload says exactly what the signed payload says.
- **The key set** carries the seven public members of each key and the two `psn:` standing
  members, and nothing else. Each kid appears once, and each key is a point on P-256.
- **Nothing in any file is email-shaped or name-shaped.** A value holding an `@` or whitespace
  fails.
- **The segments (`ct/{n}.json`, `ct/latest.json`) and the checkpoint artifact are in the byte
  form the platform publishes:** two-space indentation, LF line ends, one trailing newline,
  members in the platform's order. So are the `.swh.json` records, which this repository writes
  itself. `jwks.json` is kept byte for byte as served, but its form is not checked: no hash is
  taken over its bytes, so only its content is.

The log as a whole:

- Two copies of one segment (`ct/{n}.json` and `ct/latest.json`) are one log: the shorter is a
  prefix of the longer.
- Each closed segment's SHA-256 is the next segment's `prevSegmentSha256`. Segment 0 has none.
- `seq` runs from 0 with no gap. Timestamps never go backwards. No hash is logged twice. Every
  `ref` names an earlier entry.

The checkpoints:

- Each token is ES256 and verifies under its kid in `jwks.json`.
- On this repository the kid starts `psn-prod-`. On the dev repository it starts `psn-dev-`.
- Its file name follows from its signed `asOf` and `headSeq`.
- **Its `headSegmentSha256` is the SHA-256 of the head segment, cut at `headSeq` and rendered
  again.** This is the check that gives a checkpoint its meaning: a validly signed checkpoint
  that commits to a different log fails here. It is re-checked on every run, so it stays true as
  the log grows.
- If the entry at `headSeq` is later than `asOf`, that is printed as a note, never a failure.
  The platform currently takes `asOf` before it reads the entries, and an entry's time may run
  up to two minutes ahead, so an honest checkpoint can show this by a little.
- Taken in order of `asOf`, the checkpoints never commit to an earlier head, and no two share
  an `asOf`. `ct/checkpoint-latest.json` is the newest of them.

With `--history`, it also checks every commit that touched the log against the commit before
it. Nothing is removed, no checkpoint or record is rewritten, no file goes back to an older
version, no commit holds a file outside the layout above (even one a later commit removed), and
each step obeys the growth rules below.

### Re-rendering a segment, and the test vectors

A checkpoint commits to the head segment as it stood at `asOf`. The open segment keeps growing
after that, so a verifier takes the copy it holds, keeps the entries up to `headSeq`, writes the
document out again, and hashes it. That only works if the verifier writes exactly the bytes the
platform wrote.

**The public specification does not define those bytes.** `ct-segment.v1` describes
`prevSegmentSha256` as the SHA-256 "of the previous segment document" but fixes no
whitespace or member order. So this verifier is pinned to what the platform's renderer
publishes and to test vectors:

- The document is `JSON.stringify(document, null, 2)` plus one `\n`.
- The members are `schemaVersion, segment, startSeq, prevSegmentSha256, entries`, and in each
  entry `seq, h, typ, kind, ref, ts`. `ct/latest.json` adds `generatedAt` and `closed` at the end.
- The values are integers, null and ASCII strings only (the schema allows nothing else).
- The vectors are the first signed dev checkpoint (`asOf` 2026-10-01T00:20:21Z, `headSeq` 0)
  and the dev segment it commits to. The served `/ct/0.json` is 322 bytes and
  hashes to `da9c24cc2dae9b9ef65b5d92f2ac804aaf9f3f761435d66777188cd7734be415`, which is the
  checkpoint's `headSegmentSha256` (`tests/render.test.mjs`).

Every segment and checkpoint artifact the mirror copies must also re-render to its own exact
bytes. If the platform ever changed its byte form, the mirror would say so on the first run
rather than mis-hash quietly.

### The key set is not the out-of-band key channel

This repository copies the key set the edge serves, and checks checkpoint signatures against
that copy. Anyone able to substitute both the edge's checkpoint and the edge's key set would
pass that check, so it shows only that the two agree. What the mirror adds is history. A kid
never disappears from the key set, a kid's key material never changes, a key's validity window
never opens at a different time (a changed `notBefore` would backdate the key), and a new kid is
flagged in the run. A copy of the set served late from a cache is not mistaken for a key
leaving, for as long as a cache can hold one (25 hours after the mirror committed the newer
set), and never when the served set was generated later than the mirrored one.

The out-of-band channel is a different one: the specification provides for the key set to be
committed, with signed commits, to the public specification repository. Check a key against
that copy, not against this one.

## How the mirror decides what to commit

- **The log only grows.** Closed segments must be byte-identical to the mirrored copies. The
  open segment must extend the mirrored one. `seq` must run on, the chain must recompute, and
  checkpoint files are never rewritten.
- **A copy shorter than what is mirrored is a stale read only while a cache can explain it.**
  The edge caches `/ct/latest.json` for five minutes, `/ct/{n}.json` for a day, and `/jwks.json`
  for an hour (a day more while the origin errs). So a strict prefix of what is mirrored is
  skipped for 2 hours (`latest.json`), 26 hours (`ct/{n}.json`) or 25 hours (`jwks.json`),
  counted from the moment the mirror committed the longer copy. After that, no cache can still
  hold the older copy, and a shorter copy is an incident: the log shrank, or a kid left the key
  set. A shorter copy whose `generatedAt` is newer than the mirrored one is an incident at once,
  because it is not an old copy. A copy that is neither a prefix nor an extension is always an
  incident.
- **Which segments exist is read from `ct/latest.json`'s `segment` field.** The mirror never
  probes for the next one. A segment that closed must be served closed, and a segment the log
  names must be served at all, within 26 hours of the mirror first seeing a later segment;
  otherwise it is an incident.
- **A 404 means "not served now"** (a cache can hold an absence for a while). For a file the
  mirror already holds, that holds for the same windows; after them, a 404 is an incident (a
  published file was removed). A 5xx or no answer makes the run skip, green, with a warning.
  Before the edge serves the log at all, every run ends green with the notice "not published at
  this origin yet".
- **A setting error is not an incident.** If the mirror is empty and every key the origin
  serves is outside this repository's fence (`psn-prod-` here, `psn-dev-` on the dev
  repository), the repository variables `PSN_ENV` or `PSN_ORIGIN` are wrong. The run goes red,
  commits nothing and opens no issue. With `PSN_ORIGIN` unset the workflow is switched off: both
  jobs are skipped and it stays green.
- **"Changed" means** new entries, a numbered segment that grew, a new checkpoint, or a change
  to the key set. A run that sees only a new `generatedAt` commits nothing. When a run does
  commit, `ct/latest.json` and `jwks.json` are refreshed to the bytes served at that moment.
- **One commit per publication seen.** The commit message names the head seq, the segment, the
  newest checkpoint's `asOf`, the SHA-256 of `latest.json` as served, and the fetch time.

## Incidents

If the served log fails a check, nothing under `ct/`, `checkpoints/` or `jwks.json` moves.
Instead the run:

- commits the served bytes under `incidents/{YYYYMMDDTHHMMSSZ}/`, with a one-line
  `reason.txt` and a `files.json` that lists every served file with its URL and SHA-256;
- keeps a served file in full **only if it passed its schema and the no-names rule**. A file that
  failed keeps only its SHA-256 and the reason. Software Heritage keeps everything for ever and
  cannot honour an erasure request, so a renderer bug that leaked a personal field must not reach
  it through this folder;
- asks Software Heritage to save that commit too, so the evidence sits outside the
  Association's control;
- opens an issue and turns the run red. The same incident seen again is not recorded twice.

**Nobody repairs this repository's history.** If a push is refused, or the commit in Software
Heritage's newest snapshot is no longer in this history, the run goes red and changes nothing.
History is never rewritten by force-pushing. If it ever were, the next commit would say so under
`incidents/` and name the last Software Heritage snapshot that holds the true history.

## Software Heritage

After a commit to the log, the workflow sends a "Save Code Now" request for this repository. It
uses the Association's Software Heritage account token, sent on every call. It polls the request
every 60 seconds for up to 20 minutes; a request still running then is kept in `swh/state.json`
and picked up by the next run.

A save is done when `save_task_status` is `succeeded`, `visit_status` is `full` and
`snapshot_swhid` is set. The run then reads the snapshot and checks that its `refs/heads/main`
is the commit to archive, or a later one. If the snapshot missed the commit, the run makes one
new request (at most one per run).

For each checkpoint the snapshot holds, the run writes `checkpoints/{name}.swh.json`:

```json
{
  "checkpoint": "checkpoints/20261101T002000Z_41.jws",
  "origin_url": "https://github.com/purposesource/transparency-log",
  "snapshot_swhid": "swh:1:snp:…",
  "visit_date": "2026-11-01T01:02:03.456789+00:00",
  "visit_status": "full",
  "save_request_id": 123456,
  "save_request_url": "https://archive.softwareheritage.org/api/1/origin/save/123456/",
  "mirror_commit": "…the git commit the snapshot captured…"
}
```

`save_request_id` is null when the snapshot came from a visit this mirror did not request, such
as Software Heritage's own revisits.

A record commit is itself saved once more, and that save adds no record, so the loop stops.
The run goes red if Software Heritage refuses the token (401: it expired or was revoked, and
needs replacing; 403: forbidden, the token lacks permission), or if no full snapshot holds the
newest commit 24 hours after the workflow first asked Software Heritage for it. That moment is
kept in `swh/state.json`, so a token added late starts the clock then. A rate limit or an
outage only delays the record.

Without the token the mirror still commits, and the Software Heritage part is skipped. On the
production repository each such run warns, and the run goes red once the first log commit is
more than 24 hours old. On the dev repository it is a notice.

To check a record yourself:

```sh
curl -s "https://archive.softwareheritage.org/api/1/snapshot/<hex after swh:1:snp:>/?branches_from=refs/heads/main&branches_count=1"
```

The answer's `refs/heads/main` target is `mirror_commit`, and `git show <mirror_commit>:checkpoints/<name>.jws`
is the checkpoint.

## How this repository is protected

- A ruleset on `main` blocks force pushes and deletion, with nobody exempt. Each run checks that
  the rules are in place and goes red if they are not.
- The workflow writes with the repository's own `GITHUB_TOKEN`. The workflow as a whole is
  granted nothing; the mirror job gets `contents: write` and `issues: write` on this repository,
  and the archive job `contents: write` only. That token expires when the job ends. Pushes are
  plain `git push`, never forced, and one run at a time.
- Actions are pinned by full commit SHA. The tools have no npm dependencies.
- The only secret is the Software Heritage token, an environment secret (`SWH_TOKEN` in the
  environment `archive`) that only the archive job can read.
- Owners of the GitHub organisation can still delete this repository. That is why the Software
  Heritage copy exists: it survives that.

## Late or missing runs

GitHub may start a scheduled run late, or drop one when it is busy. The workflow runs at
37 minutes past each hour, away from the busy top of the hour. A missed run loses nothing that is
still served, because the next run reads it. A checkpoint that the edge replaced before any run
saw it would be missing from `checkpoints/`.

GitHub also switches off the schedule of a public repository after 60 days without activity.
Once the log is served, each new checkpoint is a commit, which keeps the schedule alive. A
repository whose origin does not serve the log yet makes no commits at all, so GitHub may switch
its schedule off after 60 days. The production repository is in that position until the
production edge serves the log (switch 56 of the Association's launch plan); the Association's
orchestrator re-enables the workflow at switch 56.

## Specification versions

This mirror follows `ct-segment.v1` 1.3.0, `ct-checkpoint.v1` 1.0.0 and the `Jwks` and
`CtCheckpointArtifact` components of `edge-public.v1`, all in the public
[specification repository](https://github.com/purposesource/spec). It already accepts a
`record` entry kind, planned for recording waivers, so that kind cannot raise a false incident
on the day it is first published. The tables are in `tools/lib/spec.mjs` and change in step
with the specification.

## Licence

The log files in this repository are public data published by the Purpose Source Association.
The tools (`tools/`, `tests/` and `.github/workflows/`) are licensed under the Apache License,
Version 2.0. The text is in [`tools/LICENSE`](tools/LICENSE).
