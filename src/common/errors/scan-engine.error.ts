export type ScanEngineErrorCode =
  | 'CLONE_FAILED'
  | 'TRIVY_SPAWN_FAILED'
  | 'TRIVY_EXEC_FAILED'
  | 'PARSE_FAILED'
  | 'DISK_FULL'
  | 'UNKNOWN';

/**
 * Structured error raised anywhere in the scan pipeline (clone, trivy exec,
 * stream parsing). Carries a machine-readable `code` alongside a
 * human-readable message so the worker can log/report failures consistently
 * and the GraphQL layer can eventually branch on `code` if needed.
 */
export class ScanEngineError extends Error {
  constructor(
    message: string,
    public readonly code: ScanEngineErrorCode,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'ScanEngineError';
  }
}
