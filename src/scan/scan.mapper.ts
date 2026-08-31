import { ScanRecord } from './interfaces/scan-record.interface';
import { ScanType } from './graphql/scan.type';

/**
 * ScanRecord (the storage shape, dates as ISO strings so it round-trips
 * cleanly through JSON.stringify/parse in Redis) -> ScanType (the GraphQL
 * shape, dates as `Date` so the GraphQLISODateTime scalar can serialize
 * them). Kept as an explicit mapping rather than reusing one type for both
 * layers, so storage/serialization concerns don't leak into each other.
 */
export function toScanType(record: ScanRecord): ScanType {
  return {
    id: record.id,
    repositoryUrl: record.repositoryUrl,
    status: record.status,
    criticalVulnerabilityCount: record.criticalVulnerabilityCount,
    errorMessage: record.errorMessage,
    createdAt: new Date(record.createdAt),
    updatedAt: new Date(record.updatedAt),
  };
}
