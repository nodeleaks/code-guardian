import { ScanEngineError, ScanEngineErrorCode } from './scan-engine.error';

/**
 * User-facing text for each failure mode.
 *
 * The raw `ScanEngineError.message` deliberately carries diagnostic detail -
 * subprocess stderr tails, absolute temp paths, the configured trivy binary
 * path - which is exactly what we want in the logs and exactly what must not
 * reach an unauthenticated API caller. `Scan.errorMessage` is served over a
 * public GraphQL endpoint, so it gets these sanitized strings instead: enough
 * for the caller to know what to do differently, nothing about the host.
 */
const MESSAGES: Record<ScanEngineErrorCode, string> = {
  CLONE_FAILED:
    'Could not clone the repository. Check that the URL is correct and the repository is public.',
  REPO_TOO_LARGE: 'The repository is too large to scan.',
  TRIVY_SPAWN_FAILED: 'The scanner could not be started. This is a server-side problem.',
  TRIVY_EXEC_FAILED: 'The scanner failed while analysing the repository.',
  PARSE_FAILED: 'The scan produced a report that could not be read.',
  DISK_FULL: 'The server ran out of disk space while scanning. Try again later.',
  TIMED_OUT: 'The scan took too long and was cancelled.',
  UNKNOWN: 'The scan failed for an unexpected reason.',
};

/** Sanitized, caller-safe message for anything thrown by the scan pipeline. */
export function toPublicErrorMessage(err: unknown): string {
  if (err instanceof ScanEngineError) {
    return MESSAGES[err.code] ?? MESSAGES.UNKNOWN;
  }
  return MESSAGES.UNKNOWN;
}
