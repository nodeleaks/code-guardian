# Code Guardian

A backend service that wraps [Trivy](https://github.com/aquasecurity/trivy) to scan a public
GitHub repository for vulnerabilities, designed to survive a 500MB+ scan report on a
memory-constrained pod (e.g. a 256MB Kubernetes container) without ever loading that report into
memory as a whole.

Built with **NestJS**, exposing a **GraphQL** API (Bonus B), with scans processed asynchronously
on a **BullMQ**/Redis-backed queue.

## Table of contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running](#running)
- [Using the API](#using-the-api)
- [The OOM self-test](#the-oom-self-test)
- [Error handling](#error-handling)
- [Trade-offs and design notes](#trade-offs-and-design-notes)
- [Project status / bonuses](#project-status--bonuses)

## Architecture

```
GraphQL request
      |
      v
ScanResolver  (thin: input validation, delegates immediately)
      |
      v
ScanService   (creates a QUEUED record, enqueues a BullMQ job, returns instantly)
      |
      v
ScanRepository  <----------------------------+
   (Redis: scan status/results, keyed by id) |
      ^                                      |
      |                                      |
ScanProcessor (BullMQ worker - runs off the request/response cycle)
      |
      +--> GitClonerService        (shallow git clone to a temp dir)
      +--> TrivyRunnerService      (spawns `trivy fs`, writes JSON straight to disk)
      +--> TrivyStreamParserService (streams that JSON file, extracts CRITICAL findings)
      +--> cleanup (always, via finally): removes temp repo dir + report file
```

This is the Controller / Service / Worker separation the assignment asks for:

- **Controller** = `ScanResolver` - GraphQL mutation/query, input validation, nothing else.
- **Service** = `ScanService` / `ScanRepository` - orchestration and persistence, no filesystem
  or process access.
- **Worker** = `ScanProcessor` and the `trivy/` services - all the heavy lifting (clone, spawn,
  stream-parse, cleanup) lives here, off the request path.

### Why memory stays bounded

The one rule that matters most for this assignment: **the Trivy report is never read with
`fs.readFile` and never passed through `JSON.parse`.**

`TrivyRunnerService` tells Trivy to write its JSON report directly to a file (`--output`) - the
report never passes through this process as a buffered string.

`TrivyStreamParserService` (`src/scan/trivy/trivy-stream-parser.service.ts`) then reads that file
with a `stream-chain` / `stream-json` pipeline:

1. `fs.createReadStream` reads the file in small chunks.
2. `parser()` tokenizes those chunks incrementally (never buffering the whole file).
3. `pick({ filter: 'Results' })` narrows the token stream to just the `Results` array, discarding
   Trivy's other top-level fields as they stream past.
4. `streamArray()` reassembles **one** `Results[i]` element at a time (one scan target's
   findings), emits it, then discards it before building the next one - the full `Results` array
   is never materialized.
5. Only vulnerabilities with `Severity === "CRITICAL"` are kept, and even that accumulator is
   capped (`MAX_RETAINED_VULNERABILITIES = 2000` in the same file) as a defensive bound against a
   pathological report - see [Trade-offs](#trade-offs-and-design-notes).

Backpressure is handled by `stream-chain`/`stream-json` internally, so the whole pipeline is
bounded by chunk size, not file size - this is what lets it run under `--max-old-space-size=150`
against a report far bigger than that heap limit.

> **Dependency note:** `stream-chain@4.x` and `stream-json@3.x` are ESM-only, which is
> incompatible with this project's CommonJS NestJS build. This project pins the last CommonJS
> releases (`stream-chain@^3.6.3`, `stream-json@1.9.1`) instead of switching build systems.

## Prerequisites

- Node.js 22+
- A [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) binary on
  your `PATH` (or set `TRIVY_BINARY_PATH` to an absolute path). `brew install trivy` /
  `apt install trivy` / see Trivy's docs for other platforms.
- Redis, reachable at `REDIS_HOST`/`REDIS_PORT` (a `docker-compose.yml` is provided for this -
  see below).
- `git` on your `PATH` (used indirectly via `simple-git`).

## Setup

```bash
npm install
cp .env.example .env   # defaults are fine for local dev
```

Start Redis (only external dependency needed for local dev):

```bash
docker compose up -d redis
```

## Running

```bash
npm run build
npm run start:dev     # watch mode
# or
npm run start:prod    # runs dist/main.js
```

The GraphQL endpoint (with the interactive Explorer) is at `http://localhost:3000/graphql`.

## Using the API

Queue a scan:

```graphql
mutation {
  startScan(input: { repositoryUrl: "https://github.com/OWASP/NodeGoat" }) {
    id
    status
  }
}
```

Response is immediate (`status: QUEUED`) - the clone/scan/parse pipeline runs in the background.

Poll for status/results:

```graphql
query {
  scan(id: "<id from startScan>") {
    id
    status
    criticalVulnerabilityCount
    criticalVulnerabilitiesTruncated
    criticalVulnerabilities {
      vulnerabilityId
      pkgName
      installedVersion
      fixedVersion
      title
      target
    }
    errorMessage
  }
}
```

`status` moves `QUEUED -> SCANNING -> FINISHED` (or `FAILED`, with `errorMessage` set).

Per the assignment's setup step, target repository should be your own fork of
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - fork it on GitHub first, then pass your
fork's URL as `repositoryUrl` (this is a manual one-time step on your GitHub account, not
something this service does for you).

## The OOM self-test

To prove the streaming pipeline holds up against a huge report under a constrained heap:

```bash
# 1. Generate a synthetic ~500MB+ Trivy-shaped report (streamed to disk, so this
#    itself stays memory-bounded regardless of how large you ask for):
npx ts-node scripts/generate-large-trivy-report.ts 1500 1500 fixtures/huge-trivy-report.json

# 2. Build, then run just the stream parser under a 150MB heap cap:
npm run build
node --max-old-space-size=150 scripts/oom-check.js fixtures/huge-trivy-report.json
```

This has been run against a 539MB generated fixture and completed successfully with peak RSS
around 124MB - well under the 150MB heap limit - confirming the pipeline never buffers the file
or the full `Results` array. (`scripts/oom-check.js` runs the compiled `dist/` output directly,
deliberately bypassing `ts-node` so the TypeScript compiler's own memory use isn't part of what
you're measuring.)

Full-service equivalent, per the assignment's suggested check (needs Redis + Trivy running, and a
real repo to scan rather than a synthetic fixture):

```bash
npm run start:oom-check   # node --max-old-space-size=150 dist/main.js
```

## Error handling

Every stage of the pipeline (`GitClonerService`, `TrivyRunnerService`,
`TrivyStreamParserService`) raises a typed `ScanEngineError` (`src/common/errors/scan-engine.error.ts`)
with a machine-readable `code`:

| Code | When |
|---|---|
| `CLONE_FAILED` | `git clone` failed (bad URL, private repo, network error, etc.) |
| `DISK_FULL` | Clone or Trivy write failed with `ENOSPC` (detected via stderr/message sniffing) |
| `TRIVY_SPAWN_FAILED` | The `trivy` binary couldn't be started (e.g. not installed / not on `PATH`) |
| `TRIVY_EXEC_FAILED` | `trivy` ran but exited non-zero |
| `PARSE_FAILED` | The report file wasn't valid/parseable JSON |

`ScanProcessor.process()` catches all of these (and anything unexpected) in one place, writes
`status: FAILED` with a human-readable `errorMessage` to the scan record, and - critically - still
runs cleanup (`finally` block: removes the cloned repo dir and the report file) no matter which
step failed or succeeded. Cleanup itself uses `Promise.allSettled` so a failure removing one
temp path never prevents removing the other.

## Trade-offs and design notes

- **One target assembled at a time, not one byte at a time.** `streamArray()` hands back one full
  `Results[i]` object (one scan target, with its whole `Vulnerabilities` array) per event. For
  Trivy reports this is the right granularity - a 500MB+ report comes from having very many
  targets/layers, not from one target with millions of vulnerabilities. If that assumption ever
  breaks, the same `pick`+`stream` technique can be nested one level deeper to stream
  `Results[i].Vulnerabilities` itself.
- **The retained CRITICAL list is capped** (`MAX_RETAINED_VULNERABILITIES = 2000`). In real Trivy
  output, CRITICAL findings are a small minority of total vulnerabilities - this cap is a
  defensive bound against an adversarial/unexpected report where that assumption doesn't hold,
  not something expected to be hit in practice. The true count is always tracked separately
  (`criticalVulnerabilityCount`) and `criticalVulnerabilitiesTruncated` tells the API caller if
  the list was capped, so nothing is silently dropped without a trace. This is covered by a unit
  test (`test/trivy-stream-parser.spec.ts`) using an adversarial fixture where *every*
  vulnerability is CRITICAL.
- **Redis is the source of truth for scan status/results**, kept deliberately separate from the
  BullMQ queue connection (`src/redis/redis.module.ts`) - the queue only needs to know "a job with
  this id exists"; the repository is what the API actually reads from. Records expire after
  `SCAN_RECORD_TTL_SECONDS` (default 24h) so Redis doesn't grow unbounded over time.
  Storing only the *filtered-down* critical list (not the raw report) keeps individual records
  small regardless of source report size.
- **Shallow clone (`--depth 1`).** Trivy's filesystem scanner only needs the working tree, not
  history, so cloning is bounded by repo size, not repo history size.
- **`trivy fs --scanners vuln`** (no `--severity` flag). Trivy could filter to `CRITICAL` itself
  at scan time, which would sidestep needing to stream-filter at all - deliberately not done here,
  since the assignment's point is to demonstrate handling the unfiltered, huge output correctly.
  Combining both (`--severity` at the Trivy layer *and* streaming) would be the pragmatic choice
  in a real system.
- **Job retries are disabled** (`attempts: 1`). Failures are already captured and reported via
  the scan record's `FAILED` status; a BullMQ-level retry would re-run clone+scan+cleanup against
  a job that already reported failure, which isn't obviously more useful for this use case than
  letting the caller decide whether to submit a new scan.

## Project status / bonuses

- [x] Core: async `POST`-equivalent scan mutation, background worker, status query
- [x] Bonus B: GraphQL API (this is the API - no separate REST layer)
- [ ] Bonus A: React polling frontend - not yet built
- [ ] Bonus C: `docker-compose.yml` with `mem_limit` for the app service - `docker-compose.yml`
      currently only provides Redis for local dev; the app service + memory limit is a follow-up
