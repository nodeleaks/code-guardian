/**
 * Minimal typing of the parts of the Trivy JSON report we actually consume.
 *
 * We deliberately do NOT type the full report root object: doing so would
 * imply it is ever assembled in memory as a whole, which is exactly what
 * this service must avoid. The stream parser (see trivy/trivy-stream-parser.service.ts)
 * only ever picks the `Results` array and streams it element-by-element, so
 * only `TrivyResult` (one target's worth of findings) needs a full shape.
 */

export type TrivySeverity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity: TrivySeverity;
  Title?: string;
  PrimaryURL?: string;
}

export interface TrivyResult {
  Target: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
}
