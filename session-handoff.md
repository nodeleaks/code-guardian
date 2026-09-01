# Session Handoff

## Verified Now

- What is currently working: the full unit suite is green - 13 suites / 149 tests.
  `npx tsc --noEmit`, `npx eslint` over `src/` and `test/`, and
  `npm --prefix web run typecheck` all exit 0. Both features in `feature_list.json`
  (`trivy-severity-defense-in-depth`, `paginated-vulnerability-list`) are `passing` with
  their evidence recorded; nothing is `in_progress`.
- What verification actually ran: the four commands above, plus the OOM self-test against
  a freshly generated 539MB fixture containing 112,500 CRITICAL findings. All 112,500 were
  streamed to the sink in 215 batches, largest batch 525, and the same fixture still parses
  at `--max-old-space-size=25`. That heap ceiling - not the RSS number - is the real
  evidence that the output buffer stays bounded.
- Also verified, but by the user rather than by a test: the `--severity CRITICAL` flag runs
  correctly against the real pinned Trivy binary via `docker compose up --build` (scan
  reached FINISHED with a non-zero CRITICAL count).

## Changed This Session

- Code or behavior added: the vulnerability list is no longer capped or truncated. Findings
  are appended to a `scan:<id>:vulns` Redis list in batches of 500 while the report is being
  parsed, so the full list never exists in this process, and read back through a paginated
  `criticalVulnerabilities(offset, limit)` resolver field (`limit` validated, max 200).
  `MAX_RETAINED_VULNERABILITIES` and `criticalVulnerabilitiesTruncated` are gone. Because
  findings left the scan record, a status poll no longer deserialises any of them. The web
  UI pages with Prev/Next and a `Showing X-Y of N` counter.
- Infrastructure or harness changes: none to Docker, CI, config or dependencies.
  `scripts/oom-check.{ts,js}` now pass a counting sink, so the self-test measures the same
  code path production uses.

## Broken Or Unverified

- Known defect: none known.
- Unverified path: the Redis list itself. Every test mocks the ioredis client, so no
  `RPUSH`/`LRANGE` has been issued against a real Redis, and the UI pagination has not been
  opened in a browser. Both checks were deliberately skipped this session at the user's
  direction - they are not failures, just not done.
- Risk for the next session: removing the cap moved a bound rather than eliminating it.
  How much one scan can write into Redis is now limited only by `SCAN_MAX_REPO_SIZE_MB`
  upstream and by `SCAN_RECORD_TTL_SECONDS` expiring the key; there is no explicit ceiling
  on stored findings. Worth reconsidering if Redis capacity is ever tight. Separately, the
  `coverage/` report on disk is stale (dated 25 August).

## Next Best Step

- Highest-priority unfinished feature: none in `feature_list.json`. The next session picks
  work from the user's request and marks it `in_progress` before starting.
- Why it is next: the one open thread is verification. `docker compose up --build`, a scan
  of a real repository, then paging the results through both the API and the UI closes both
  skipped checks in a single pass.
- What counts as passing: two adjacent pages (`offset: 0` and `offset: 10` at `limit: 10`)
  return disjoint, correctly ordered findings, and the UI counter agrees with
  `criticalVulnerabilityCount`.
- What must not change during that step: do not weaken or delete tests, and do not rewrite
  the feature list to hide unfinished work (see `CLAUDE.md` Rules). Do not remove the
  `Severity !== 'CRITICAL'` check in `trivy-stream-parser.service.ts` as "dead code" - it is
  intentional boundary validation against an external binary. Do not reintroduce findings
  into the scan record: keeping them in their own key is what makes the 2-second poll cheap.

## Commands

- Startup: `docker compose up --build`
- Verification: `npm run test`
- Focused debug command: `npx jest test/trivy-stream-parser.spec.ts -t "stores every finding"`
- Memory check: `node --max-old-space-size=150 scripts/oom-check.js fixtures/huge-trivy-report.json`
