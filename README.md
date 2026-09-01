# Code Guardian

A backend service that wraps [Trivy](https://github.com/aquasecurity/trivy) to scan a public
GitHub repository for vulnerabilities, designed to survive a 500MB+ scan report on a
memory-constrained pod (e.g. a 256MB Kubernetes container) without ever loading that report into
memory as a whole.

Built with **NestJS**, exposing a **GraphQL** API, with scans processed asynchronously
on a **BullMQ**/Redis-backed queue.

A small [web UI](#web-ui-web) is also included for interacting with the API without writing
GraphQL queries by hand.

## Quick start

From nothing to a working UI. You need [Docker](https://docs.docker.com/get-docker/) and
[Node.js 24+](https://nodejs.org/) - Trivy, Redis and the vulnerability database all come from
containers, so there is nothing else to install.

Give Docker at least **2GB of memory** and **4GB of free disk**: the `trivy-db` step runs with
`mem_limit: 1500m`, and the image plus the cached vulnerability database come to about 2.3GB. On
Docker Desktop these are under Settings → Resources.

**Terminal 1 - the API:**

```bash
git clone https://github.com/nodeleaks/code-guardian.git
cd code-guardian
docker compose up --build
```

The first run builds the image and downloads Trivy's ~1.3GB vulnerability database into a named
volume, so it prints nothing for a while - that is not a hang. On a fast connection the whole
cold start takes about a minute; on a slow one the database download dominates. It happens once:
later runs reuse the volume. The stack is ready when you see
`Code Guardian listening on http://localhost:3000/graphql`.

**Terminal 2 - the web UI:**

```bash
cd code-guardian/web
npm install
cp .env.example .env
npm run dev
```

Open <http://localhost:5173>, paste a public GitHub repository URL - for example
`https://github.com/nodeleaks/NodeGoat` - and press **Start**. The scan runs in the background
and the page polls until it finishes.

The default ports already line up (`VITE_API_URL` → 3000, `CORS_ORIGIN` → 5173), so no
configuration is needed. To run the API without Docker, or to understand why the stack is split
this way, see [Running it](#running-it).

## Table of contents

- [Code Guardian](#code-guardian)
  - [Quick start](#quick-start)
  - [Table of contents](#table-of-contents)
  - [Architecture](#architecture)
    - [Why memory stays bounded](#why-memory-stays-bounded)
  - [Trivy delivery: Docker vs. local binary](#trivy-delivery-docker-vs-local-binary)
  - [Running it](#running-it)
    - [Option 1: Docker Compose (recommended - no local Trivy install needed)](#option-1-docker-compose-recommended---no-local-trivy-install-needed)
      - [Why there's a separate `trivy-db` service](#why-theres-a-separate-trivy-db-service)
    - [Option 2: Local Node + local Trivy](#option-2-local-node--local-trivy)
  - [Configuration](#configuration)
  - [Using the API](#using-the-api)
  - [Web UI (`web/`)](#web-ui-web)
  - [The OOM self-test](#the-oom-self-test)
    - [Containerized version](#containerized-version)
  - [Error handling](#error-handling)
  - [Trade-offs and design notes](#trade-offs-and-design-notes)

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
5. Only vulnerabilities with `Severity === "CRITICAL"` are kept, and they accumulate no further
   than `FLUSH_BATCH_SIZE` (500) before being handed to a sink and dropped. The output side is
   therefore bounded by the batch size, not by how many findings the report contains.

Backpressure is handled on both sides. Upstream, `stream-chain`/`stream-json` pause the source
read stream while downstream processing catches up. Downstream, the parser pauses the pipeline
itself while a batch is being written, because the sink is async and the `data` handler is not.
The whole pipeline is bounded by chunk and batch size rather than file size - which is what lets
it run under `--max-old-space-size=150` against a report far bigger than that heap limit (in
fact, far below it - see [The OOM self-test](#the-oom-self-test)).

> **Dependency note:** `stream-chain@4.x` and `stream-json@3.x` are ESM-only, which is
> incompatible with this project's CommonJS NestJS build. This project pins the last CommonJS
> releases (`stream-chain@^3.6.3`, `stream-json@1.9.1`) instead of switching build systems.

## Trivy delivery: Docker vs. local binary

The code always calls Trivy the same way - `child_process.spawn('trivy', [...])`
(`TrivyRunnerService`) - it has no idea whether that binary came from your `PATH` or from inside
a container. What changes between environments is only *how `trivy` gets onto the machine this
process runs on*:

- **Bundled in the app's own image (what this repo does for Docker).** `Dockerfile` installs both
  `git` and `trivy` into the same image as the Node app. At runtime it's the exact same
  `spawn('trivy', ...)` call as running locally - no extra moving parts.
- **Installed locally** if you're not using Docker at all (Option 2 below).

Deliberately **not** done: spawning Trivy via `docker run aquasec/trivy ...` from inside the
service (Docker-outside-of-Docker, needing `/var/run/docker.sock` mounted in). Two reasons:

1. Mounting the Docker socket into a container is effectively root access to the host - real K8s
   clusters almost universally block it, so it wouldn't reflect how this would actually deploy.
2. If Trivy runs in a sibling
   container with no memory limit of its own, the `mem_limit: 200m` on the *app* container is only
   constraining a process that isn't doing the heavy lifting - `trivy fs` writing the huge report
   and this process reading it back both need to happen **inside** the constrained boundary for
   the OOM test to mean anything.

The `trivy-db` init container isn't an exception to that. It only *downloads* the vulnerability DB
into a shared volume and exits; it never scans. Every part of the work the OOM test is about - the
clone, `trivy fs`, and the streaming parse - still happens inside the 200m boundary. See
[Why there's a separate `trivy-db` service](#why-theres-a-separate-trivy-db-service) for the
measurements that forced the split.

## Running it

There are two ways to run this, and the difference is really just "where does the `trivy`
binary come from."

### Option 1: Docker Compose (recommended - no local Trivy install needed)

`docker-compose.yml` builds the service from `Dockerfile`, which bakes `git` and `trivy` into the
same image as the Node app (see [Trivy delivery](#trivy-delivery-docker-vs-local-binary) below for
why it's packaged this way rather than shelling out to `docker run`), and runs it alongside Redis:

```bash
docker compose up --build
```

The `app` service also carries memory's constraint - `mem_limit: 200m` / `memswap_limit: 200m` -
plus `NODE_OPTIONS=--max-old-space-size=150`, mirroring the assignment's own OOM self-test but
applied to the whole container, not just a local `node` invocation. The GraphQL endpoint is at
`http://localhost:3000/graphql`.

#### Why there's a separate `trivy-db` service

The stack starts a short-lived `trivy-db` container before `app`, using the same image, purely to
run `trivy fs --download-db-only` into a shared `trivy-cache` volume. `app` then scans with
`TRIVY_SKIP_DB_UPDATE=true` and never downloads anything itself.

That split exists because *downloading* Trivy's vulnerability DB and *scanning with* it have wildly
different memory profiles. Measured on this image:

| Phase | Peak container memory |
| --- | --- |
| `trivy fs` with a warm cache and `--skip-db-update` | **~47 MB** (succeeds even at `-m 128m`) |
| `trivy fs` with a cold cache (downloads the DB) | **OOM-killed at 200m and at 512m**; needs ~1 GB |

The DB is a ~1.3 GB bolt file, and extracting it fills the cgroup with dirty page cache faster than
the kernel can write it back - with `memswap_limit == mem_limit` there's no swap to fall back on, so
the cgroup OOM killer fires and takes PID 1 (Node) with it. The container dies with **exit code
137** before the scan even starts.

So the download gets its own container with room to breathe, and the 200m limit on `app` measures
what it's actually meant to measure: the clone, the scan, and the streaming parse. Because the cache
lives in a named volume, the 1.3 GB download survives `docker compose down` and happens once, not on
every cold start. Re-running `docker compose up` re-runs `trivy-db`, which is a no-op while the
cached DB is still fresh.

To pin a specific Trivy version for reproducible builds instead of "whatever's latest at build
time," uncomment the `args: TRIVY_VERSION:` line in `docker-compose.yml`.

### Option 2: Local Node + local Trivy

Prerequisites:

- Node.js 24+
- A [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) binary on
  your `PATH` (or set `TRIVY_BINARY_PATH` to an absolute path). `brew install trivy` /
  `apt install trivy` / see Trivy's docs for other platforms.
- `git` on your `PATH` (used indirectly via `simple-git`).
- Redis, reachable at `REDIS_HOST`/`REDIS_PORT` - `docker compose up -d redis` starts just that
  piece if you don't want to install Redis natively either.

```bash
npm install
cp .env.example .env   # defaults are fine for local dev
docker compose up -d redis

npm run build
npm run start:dev     # watch mode
# or
npm run start:prod    # runs dist/main.js
```

The GraphQL endpoint is at `http://localhost:3000/graphql`.

The interactive Apollo Explorer (and the schema introspection it relies on) is gated behind
`GRAPHQL_PLAYGROUND` and **defaults to off** - exposing a full schema dump on an
unauthenticated endpoint isn't something that should depend on remembering to set `NODE_ENV`.
The Docker Compose stack sets `GRAPHQL_PLAYGROUND=true` for you since it's a local demo; running
locally via Option 2, set it yourself (`GRAPHQL_PLAYGROUND=true npm run start:dev`) if you want
the Explorer.

## Configuration

Every setting has a working default - `cp .env.example .env` is enough for local dev. The full
list lives in `.env.example`; the ones worth knowing about:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port. |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | Queue + status store. |
| `REDIS_PASSWORD` | *(unset)* | Set for a Redis requiring AUTH. |
| `REDIS_TLS` | `false` | `true` to connect over TLS (managed Redis usually needs this). |
| `TRIVY_BINARY_PATH` | `trivy` | Path or command name of the Trivy binary. |
| `SCAN_RECORD_TTL_SECONDS` | `86400` | How long a finished/failed scan is kept in Redis. |
| `SCAN_TIMEOUT_MS` | `300000` | Wall-clock cap applied separately to `git clone` and `trivy fs`. |
| `SCAN_MAX_REPO_SIZE_MB` | `1024` | Reject a cloned tree larger than this before scanning. |
| `SCAN_MAX_QUEUE_DEPTH` | `100` | Refuse new scans once this many jobs are waiting. |
| `CORS_ORIGIN` | `http://localhost:5173` | Comma-separated origins allowed to call the API. |
| `GRAPHQL_PLAYGROUND` | `false` | Serves the Apollo Explorer **and** enables introspection. |

Values are validated with Joi at startup, so a malformed one (`PORT=abc`) fails the boot with a
clear message rather than silently becoming `NaN`.

## Using the API

Queue a scan:

```graphql
mutation {
  startScan(input: { repositoryUrl: "https://github.com/nodeleaks/NodeGoat" }) {
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
    errorMessage
  }
}
```

`status` moves `QUEUED -> SCANNING -> FINISHED` (or `FAILED`, with `errorMessage` set).

Findings are a separate, paginated field, so polling for status does not drag the whole list back
on every tick. `criticalVulnerabilityCount` is the total to page through:

```graphql
query {
  scan(id: "<id from startScan>") {
    criticalVulnerabilityCount
    criticalVulnerabilities(offset: 0, limit: 50) {
      vulnerabilityId
      pkgName
      installedVersion
      fixedVersion
      title
      target
    }
  }
}
```

`offset` defaults to `0` and `limit` to `50`; `limit` is capped at `200` per request. Ordering is
the order the parser produced findings in, and the stored list is append-only and never reordered,
so paging with plain offsets is stable - element N is the same finding on every read. Nothing is
truncated: every CRITICAL finding is reachable by paging.

Per the assignment's setup step, target repository should be your own fork of
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - fork it on GitHub first, then pass your
fork's URL as `repositoryUrl` (this is a manual one-time step on your GitHub account, not
something this service does for you).

## Web UI (`web/`)

A small React (Vite + TypeScript) frontend lives in `web/` and drives the API above: enter a
repository URL, click **Start**, and it polls `scan(id)` every 2 seconds until the scan reaches
`FINISHED` (or `FAILED`), then fetches the findings one page at a time and renders them with
Prev/Next controls and a `Showing X-Y of N` counter. The poll and the page fetch are separate
requests on purpose: the poll only carries status and counts. It's a separate app/process
from the API - `docker-compose.yml` does not start it, so it's always run on its own, whether the
API is running via Docker Compose or `npm run start:dev`.

Prerequisites: Node.js 24+ and the API already running and reachable (see
[Running it](#running-it) above).

```bash
cd web
npm install
cp .env.example .env   # default VITE_API_URL matches Option 1/2's default port
npm run dev
```

Open `http://localhost:5173`. The default `VITE_API_URL` (`http://localhost:3000/graphql`) and the
API's default `CORS_ORIGIN` (`http://localhost:5173`, see `.env.example` at the repo root) already
match each other, so no config changes are needed for local dev with default ports - only override
either if you've moved the API or the frontend off their default ports.

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

Measured against a 539MB generated fixture containing **112,500 CRITICAL findings**, all of which
are streamed through to the sink - none are dropped. `scripts/oom-check.js` passes a sink that
counts each batch and discards it, standing in for the Redis-backed one used in production, so
the code path under measurement is the real one and no Redis is needed.

The decisive result is not an RSS number but the heap ceiling: the same fixture parses
successfully at **`--max-old-space-size=25`**. Retaining even a fraction of 112,500 findings would
not fit in a 25MB heap, so this is direct evidence that the output buffer stays bounded by
`FLUSH_BATCH_SIZE` rather than growing with the number of findings.

Resident set size is a weaker signal and worth reading carefully: on the machine these numbers
were taken on, this fixture peaks at ~214MB RSS, and it stays in the 190-210MB range whether the
heap cap is 150MB or 25MB. That flatness is the giveaway - RSS here is dominated by allocator and
GC headroom plus native stream buffers, not by retained findings. For reference, the previous
truncating implementation measured ~203MB on the same machine with the same fixture, so removing
truncation cost roughly 10MB (~5%): the price of actually materialising and handing off 112,500
findings instead of skipping 110,500 of them at a cap check. An earlier ~124MB figure recorded
here does not reproduce on this machine even with that old code, so treat RSS as
environment-dependent and the heap ceiling as the real guarantee.

(`scripts/oom-check.js` runs the compiled `dist/` output directly, deliberately bypassing
`ts-node` so the TypeScript compiler's own memory use isn't part of what you're measuring.)

Full-service equivalent, per the assignment's suggested check (needs Redis + Trivy running, and a
real repo to scan rather than a synthetic fixture):

```bash
npm run start:oom-check   # node --max-old-space-size=150 dist/main.js
```

### Containerized version

`docker compose up --build` already runs the whole service under `mem_limit: 200m` /
`memswap_limit: 200m` with `NODE_OPTIONS=--max-old-space-size=150` baked into `docker-compose.yml`
- so submitting a real scan (`startScan` mutation against a real repo URL) through the running
container **is** a self-test: clone, `trivy fs`, and the stream parser all have to fit
in that 200MB boundary together, not just the parser in isolation. Watch it stay up rather than
get OOM-killed:

```bash
docker compose up --build
docker stats code-guardian-app-1   # watch memory while a scan runs
```

Measured on a real run: scanning [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) through the
containerized stack peaks at **~73MB of the 200MB limit** and reports 11 CRITICAL findings, so the
clone, the `trivy fs` run and the streaming parse together leave roughly 60% of the boundary
unused.

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
- **Nothing is truncated; findings are paginated instead.** An earlier version capped the
  retained list at 2,000 findings and reported the overflow via a `criticalVulnerabilitiesTruncated`
  flag. That kept memory bounded but made the rest of the list unreachable. Findings now live in
  their own Redis list (`scan:<id>:vulns`), written in batches of 500 as the report is parsed and
  read back a page at a time, so memory stays bounded at both ends without discarding anything.
  This is covered by a unit test (`test/trivy-stream-parser.spec.ts`) using an adversarial fixture
  where *every* vulnerability is CRITICAL: it asserts that every counted finding reaches the sink
  and that no single batch exceeds the flush size.

  The residual risk that the old cap covered has moved rather than vanished: how much a single
  scan can put into Redis is now bounded only by `SCAN_MAX_REPO_SIZE_MB` upstream (a repo that
  large can only carry so many packages) and by `SCAN_RECORD_TTL_SECONDS` expiring the key. There
  is no longer an explicit ceiling on the number of stored findings. In a deployment where Redis
  capacity is tight, that ceiling is the thing to add back.
- **Redis is the source of truth for scan status/results**, kept deliberately separate from the
  BullMQ queue connection (`src/redis/redis.module.ts`) - the queue only needs to know "a job with
  this id exists"; the repository is what the API actually reads from. Records expire after
  `SCAN_RECORD_TTL_SECONDS` (default 24h) so Redis doesn't grow unbounded over time - the TTL is
  reapplied to the findings list on every batch, so a scan that dies mid-parse cannot leave an
  immortal partial list behind. Each scan uses two keys: `scan:<id>` for status and counts, and
  `scan:<id>:vulns` for the findings. Keeping them apart is what makes the 2-second status poll
  cheap - it never deserialises a single finding.
- **Shallow clone (`--depth 1`).** Trivy's filesystem scanner only needs the working tree, not
  history, so cloning is bounded by repo size, not repo history size.
- **Both filtering layers are on: `trivy fs --scanners vuln --severity CRITICAL`, *and* the
  streaming filter.** Trivy discarding the other severities before it writes the report is what
  makes the file on disk small - fewer bytes for `createReadStream` to read and fewer tokens for
  `stream-json` to tokenize, which is where the actual saving is. It is *not* a saving in the
  parser's `for` loop: that loop is needed regardless, because it also produces `totalCount` and
  batches findings out to the sink.

  The parser's own `Severity !== 'CRITICAL'` check is deliberately kept rather than deleted as
  now-dead code. It is validation at the boundary with an external process, not a redundant
  internal invariant: nothing in the type system proves that the installed binary (whose version
  and path are operator-supplied via `TRIVY_VERSION` / `TRIVY_BINARY_PATH`) honours `--severity`.
  Should that flag ever be dropped in a refactor of `runFilesystemScan`, the parser keeps
  returning a correct result instead of silently writing LOW findings into Redis labelled
  CRITICAL. The cost is one string comparison per vulnerability, against a pipeline already
  dominated by file I/O.

  Filtering at the Trivy layer does not weaken what this project set out to demonstrate. Handling
  unfiltered, 500MB+ output in bounded memory is proven independently of whatever `trivy fs`
  happens to emit - by the synthetic fixture in `scripts/generate-large-trivy-report.ts` (which
  deliberately makes only 1 in 20 findings CRITICAL) and by the adversarial fixture in
  `test/trivy-stream-parser.spec.ts` (where *every* finding is CRITICAL, exercising the cap).
- **Job retries are disabled** (`attempts: 1`). Failures are already captured and reported via
  the scan record's `FAILED` status; a BullMQ-level retry would re-run clone+scan+cleanup against
  a job that already reported failure, which isn't obviously more useful for this use case than
  letting the caller decide whether to submit a new scan.
