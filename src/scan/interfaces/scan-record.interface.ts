export enum ScanStatus {
  QUEUED = 'QUEUED',
  SCANNING = 'SCANNING',
  FINISHED = 'FINISHED',
  FAILED = 'FAILED',
}

export interface CriticalVulnerability {
  /** Synthetic id so the GraphQL type has a stable `ID!` field. */
  id: string;
  vulnerabilityId: string;
  pkgName: string;
  installedVersion?: string;
  fixedVersion?: string;
  severity: 'CRITICAL';
  title?: string;
  target: string;
}

/**
 * Metadata only. The findings themselves are NOT stored here - they live in a
 * separate Redis list (see ScanRepository.appendVulnerabilities), written
 * incrementally as the report is parsed and read back a page at a time. That
 * keeps this record small and cheap to fetch, which matters because the web
 * client polls it every 2 seconds while a scan runs.
 */
export interface ScanRecord {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  /** Total number of CRITICAL findings stored, and the `total` for pagination. */
  criticalVulnerabilityCount: number;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScanJobData {
  scanId: string;
  repositoryUrl: string;
}

export const SCAN_QUEUE_NAME = 'scan';
