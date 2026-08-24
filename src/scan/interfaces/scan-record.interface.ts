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

export interface ScanRecord {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  criticalVulnerabilities: CriticalVulnerability[];
  /** True number of CRITICAL findings, even if the list above was capped (see TrivyStreamParserService). */
  criticalVulnerabilityCount: number;
  /** True if criticalVulnerabilityCount exceeded the list's retention cap. */
  criticalVulnerabilitiesTruncated: boolean;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScanJobData {
  scanId: string;
  repositoryUrl: string;
}

export const SCAN_QUEUE_NAME = 'scan';
