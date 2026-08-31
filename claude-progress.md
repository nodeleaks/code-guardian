# Progress Log

<!--
This filename is kept for compatibility with the course examples. The file is
agent-agnostic: Codex, Claude Code, OpenHands, and other coding agents can use
it. Read it at session startup and update it before handoff through the
repository's agent instructions; no agent updates it automatically.
-->

This is a generic repository-local session progress log. The
`claude-progress.md` filename is a historical course convention, not a
Claude Code requirement. Any coding agent can use it when the repository's
instructions tell it to read the file at startup and update it before handoff;
agents do not update it automatically.

## Current Verified State

- Repository root: `/Users/andriialiabiev/cg/code-guardian`
- Standard startup path: `docker compose up --build`
- Standard verification path: `npm run test`
- Current highest-priority unfinished feature: none - both
  `trivy-severity-defense-in-depth` and `paginated-vulnerability-list` are `passing`;
  no feature is currently `in_progress`.
- Current blocker: none

## Session Log

### Session 001

- Date: 2026-08-31
- Goal: Implement the third item from README "Trade-offs and design notes" - run Trivy
  with `--severity CRITICAL` so both filtering layers (Trivy's own filter and the
  streaming filter) are active, rather than relying on the parser alone.
- Completed: Added `--severity CRITICAL` to the argument list in
  `TrivyRunnerService.runFilesystemScan`. Updated the spec that pins the exact `spawn`
  argument array. Rewrote the corresponding README trade-off to describe both layers.
  `TrivyStreamParserService` was left unchanged on purpose - its
  `Severity !== 'CRITICAL'` check is boundary validation against an external binary
  whose behaviour the type system cannot guarantee, so it stays as the second,
  independent layer.
- Verification run: `npm run test`, `npx tsc --noEmit`, and `npx eslint` on both
  changed source files.
- Evidence captured: 12 suites / 127 tests passed; typecheck reported "No errors found"
  (exit 0); eslint reported "No issues found" (exit 0). Recorded in `feature_list.json`
  under `trivy-severity-defense-in-depth`.
- Commits: see `git log` for the commit touching
  `src/scan/trivy/trivy-runner.service.ts` on branch `dev`.
- Files or artifacts updated: `src/scan/trivy/trivy-runner.service.ts`,
  `test/trivy-runner.service.spec.ts`, `README.md`, `feature_list.json`,
  `claude-progress.md`, `session-handoff.md`.
- Known risk or unresolved issue: verification in this session was unit-level only; no
  test here executes the real `trivy` binary. That gap has since been closed outside the
  session - the user ran the containerized end-to-end path themselves (see Session 002).
  The `coverage/` report on disk predates this session and is stale.
- Next best step: run a real scan through `docker compose up --build` to confirm the
  Trivy binary accepts the new flag and that reports still parse.

### Session 002

- Date: 2026-08-31
- Goal: Let the whole vulnerability list be viewed. Previously the parser kept only the
  first 2,000 findings and discarded the rest, so pagination alone would not have shown
  anything new - the storage had to change too.
- Completed: Findings moved out of the `scan:<id>` JSON record into a `scan:<id>:vulns`
  Redis list, appended in batches of 500 while the report is still being parsed, so the
  full list never exists in this process. `MAX_RETAINED_VULNERABILITIES` and the
  `criticalVulnerabilitiesTruncated` flag are gone. `criticalVulnerabilities` is now a
  paginated `@ResolveField` taking `offset`/`limit` (validated, `limit` capped at 200),
  which also means a status poll no longer reads any findings. The web UI pages through
  with Prev/Next and a `Showing X-Y of N` counter.
  Also recorded, from the user's own containerized run: the `--severity CRITICAL` flag
  from Session 001 works against the real pinned Trivy binary.
- Verification run: `npm run test`, `npx tsc --noEmit`, `npx eslint` over `src/` and
  `test/`, `npm --prefix web run typecheck`, and the OOM self-test against a freshly
  generated 539MB fixture.
- Evidence captured: 13 suites / 149 tests passed; typecheck, lint and web typecheck all
  exit 0. OOM self-test: 112,500 CRITICAL findings streamed in 215 batches, largest batch
  525, and the same fixture still parses at `--max-old-space-size=25` - which retaining
  the findings could not do. Memory cost of removing truncation measured directly against
  the old parser on this machine: ~203MB RSS before, ~214MB after.
- Commits: see `git log` for the commit touching `src/scan/scan.repository.ts` on `dev`.
- Files or artifacts updated: `src/scan/` (interfaces, repository, parser, processor,
  resolver, service, mapper, GraphQL types, new `dto/vulnerability-page.args.ts`),
  `scripts/oom-check.{ts,js}`, `web/src/{api.ts,App.tsx,App.css}`, specs in `test/`
  including the new `vulnerability-page.args.spec.ts`, `README.md`, and the harness files.
- Known risk or unresolved issue: the Redis list path is exercised only against a mocked
  ioredis client - no test drives a real `RPUSH`/`LRANGE`. The UI pagination has not been
  opened in a browser. Both end-to-end checks were deliberately skipped this session at
  the user's direction. Separately, removing the cap means the number of findings a single
  scan can put into Redis is now bounded only by `SCAN_MAX_REPO_SIZE_MB` upstream and the
  record TTL; there is no explicit ceiling any more.
- Next best step: run `docker compose up --build`, scan a real repository, and page
  through the results in both the API and the UI - that closes the two checks skipped
  here in one pass.