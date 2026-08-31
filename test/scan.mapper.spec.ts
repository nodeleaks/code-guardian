import { toScanType } from '../src/scan/scan.mapper';
import { ScanStatus, type ScanRecord } from '../src/scan/interfaces/scan-record.interface';

describe('ScanMapper', () => {
  it('converts createdAt/updatedAt from ISO strings to Date instances', () => {
    const now = new Date().toISOString();
    const record: ScanRecord = {
      id: 'scan-123',
      repositoryUrl: 'https://github.com/owner/repo',
      status: ScanStatus.FINISHED,
      criticalVulnerabilityCount: 0,
      createdAt: now,
      updatedAt: now,
    };

    const result = toScanType(record);

    expect(result.createdAt).toBeInstanceOf(Date);
    expect(result.updatedAt).toBeInstanceOf(Date);
    expect(result.createdAt.toISOString()).toBe(now);
    expect(result.updatedAt.toISOString()).toBe(now);
  });

  it('passes through all other fields unchanged', () => {
    const record: ScanRecord = {
      id: 'scan-456',
      repositoryUrl: 'https://github.com/nodeleaks/code-guardian',
      status: ScanStatus.FINISHED,
      criticalVulnerabilityCount: 5,
      createdAt: '2026-08-25T10:00:00.000Z',
      updatedAt: '2026-08-25T10:05:00.000Z',
    };

    const result = toScanType(record);

    expect(result.id).toBe(record.id);
    expect(result.repositoryUrl).toBe(record.repositoryUrl);
    expect(result.status).toBe(record.status);
    expect(result.criticalVulnerabilityCount).toBe(5);
  });

  it('handles missing errorMessage when not present', () => {
    const record: ScanRecord = {
      id: 'scan-789',
      repositoryUrl: 'https://github.com/owner/repo',
      status: ScanStatus.FINISHED,
      criticalVulnerabilityCount: 0,
      createdAt: '2026-08-25T10:00:00.000Z',
      updatedAt: '2026-08-25T10:00:00.000Z',
    };

    const result = toScanType(record);

    expect(result.errorMessage).toBeUndefined();
  });

  it('passes through errorMessage when present', () => {
    const record: ScanRecord = {
      id: 'scan-999',
      repositoryUrl: 'https://github.com/owner/repo',
      status: ScanStatus.FAILED,
      criticalVulnerabilityCount: 0,
      errorMessage: '[CLONE_FAILED] Repository not found',
      createdAt: '2026-08-25T10:00:00.000Z',
      updatedAt: '2026-08-25T10:00:00.000Z',
    };

    const result = toScanType(record);

    expect(result.errorMessage).toBe('[CLONE_FAILED] Repository not found');
  });
});
