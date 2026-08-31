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
- Current highest-priority unfinished feature: none - `trivy-severity-defense-in-depth`
  is `passing`; no feature is currently `in_progress`.
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
- Known risk or unresolved issue: verification is unit-level; the change alters the real
  `trivy` command line, and no test in this repository executes the real binary. The
  flag itself was therefore not exercised end to end in this session - the
  `docker compose up --build` path was not run. The `coverage/` report on disk predates
  this session and is stale.
- Next best step: run a real scan through `docker compose up --build` to confirm the
  Trivy binary accepts the new flag and that reports still parse; that is the one claim
  this session could not verify.

### Session 002

- Date:
- Goal:
- Completed:
- Verification run:
- Evidence captured:
- Commits:
- Files or artifacts updated:
- Known risk or unresolved issue:
- Next best step: