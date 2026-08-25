import { ConfigService } from '@nestjs/config';
import type Redis from 'ioredis';
import { ScanRepository } from '../src/scan/scan.repository';
import { ScanStatus, type ScanRecord, type CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

describe('ScanRepository', () => {
  let fakeRedis: jest.Mocked<Pick<Redis, 'set' | 'get'>>;
  let fakeConfigService: jest.Mocked<Partial<ConfigService>>;
  let repository: ScanRepository;
  const TTL_SECONDS = 3600;

  beforeEach(() => {
    fakeRedis = {
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn(),
    };

    fakeConfigService = {
      get: jest.fn().mockReturnValue(TTL_SECONDS),
    };

    repository = new ScanRepository(
      fakeRedis as unknown as Redis,
      fakeConfigService as unknown as ConfigService<never, true>,
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    it('calls redis.set with scan key, stringified record, EX, and TTL', async () => {
      const record: ScanRecord = {
        id: 'scan-123',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.QUEUED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:00:00.000Z',
      };

      await repository.create(record);

      expect(fakeRedis.set).toHaveBeenCalledWith(
        'scan:scan-123',
        JSON.stringify(record),
        'EX',
        TTL_SECONDS,
      );
    });
  });

  describe('findById', () => {
    it('returns null when redis.get resolves null', async () => {
      fakeRedis.get.mockResolvedValue(null);

      const result = await repository.findById('nonexistent');

      expect(result).toBeNull();
    });

    it('returns null when redis.get returns null', async () => {
      fakeRedis.get.mockResolvedValue(null);

      const result = await repository.findById('nonexistent');

      expect(result).toBeNull();
    });

    it('parses and returns the record when found', async () => {
      const record: ScanRecord = {
        id: 'scan-456',
        repositoryUrl: 'https://github.com/nodeleaks/code-guardian',
        status: ScanStatus.FINISHED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:05:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(record));

      const result = await repository.findById('scan-456');

      expect(result).toEqual(record);
      expect(fakeRedis.get).toHaveBeenCalledWith('scan:scan-456');
    });
  });

  describe('updateStatus', () => {
    it('patches the status field and stamps updatedAt', async () => {
      const existingRecord: ScanRecord = {
        id: 'scan-789',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.QUEUED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:00:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));

      await repository.updateStatus('scan-789', ScanStatus.SCANNING);

      const setCall = fakeRedis.set.mock.calls[0];
      expect(setCall[0]).toBe('scan:scan-789');
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.status).toBe(ScanStatus.SCANNING);
      expect(updatedRecord.repositoryUrl).toBe(existingRecord.repositoryUrl);
      expect(new Date(updatedRecord.updatedAt).getTime()).toBeGreaterThan(
        new Date(existingRecord.updatedAt).getTime(),
      );
    });

    it('does not call redis.set when record is not found (TTL-expired no-op)', async () => {
      fakeRedis.get.mockResolvedValue(null);

      await repository.updateStatus('expired-scan', ScanStatus.SCANNING);

      expect(fakeRedis.set).not.toHaveBeenCalled();
    });
  });

  describe('markFinished', () => {
    it('patches status FINISHED and vulnerability fields', async () => {
      const existingRecord: ScanRecord = {
        id: 'scan-abc',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.SCANNING,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:02:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));

      const vulns: CriticalVulnerability[] = [
        {
          id: 'vuln-1',
          vulnerabilityId: 'CVE-2021-1234',
          pkgName: 'lodash',
          installedVersion: '4.17.19',
          fixedVersion: '4.17.21',
          severity: 'CRITICAL',
          title: 'Prototype pollution',
          target: 'package-lock.json',
        },
      ];

      await repository.markFinished('scan-abc', vulns, 2, true);

      const setCall = fakeRedis.set.mock.calls[0];
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.status).toBe(ScanStatus.FINISHED);
      expect(updatedRecord.criticalVulnerabilities).toEqual(vulns);
      expect(updatedRecord.criticalVulnerabilityCount).toBe(2);
      expect(updatedRecord.criticalVulnerabilitiesTruncated).toBe(true);
    });

    it('does not call redis.set when record is not found (TTL-expired no-op)', async () => {
      fakeRedis.get.mockResolvedValue(null);

      await repository.markFinished('expired', [], 0, false);

      expect(fakeRedis.set).not.toHaveBeenCalled();
    });
  });

  describe('markFailed', () => {
    it('patches status FAILED and errorMessage', async () => {
      const existingRecord: ScanRecord = {
        id: 'scan-def',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.SCANNING,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:02:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));

      await repository.markFailed('scan-def', '[CLONE_FAILED] Repository not found');

      const setCall = fakeRedis.set.mock.calls[0];
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.status).toBe(ScanStatus.FAILED);
      expect(updatedRecord.errorMessage).toBe('[CLONE_FAILED] Repository not found');
    });

    it('does not call redis.set when record is not found (TTL-expired no-op)', async () => {
      fakeRedis.get.mockResolvedValue(null);

      await repository.markFailed('expired', 'some error');

      expect(fakeRedis.set).not.toHaveBeenCalled();
    });
  });

  describe('read-modify-write behavior', () => {
    it('preserves fields not included in the patch', async () => {
      const existingRecord: ScanRecord = {
        id: 'scan-ghi',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.QUEUED,
        criticalVulnerabilities: [
          {
            id: 'v1',
            vulnerabilityId: 'CVE-123',
            pkgName: 'pkg1',
            installedVersion: '1.0.0',
            fixedVersion: '2.0.0',
            severity: 'CRITICAL',
            title: 'Test',
            target: 'target1',
          },
        ],
        criticalVulnerabilityCount: 1,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:00:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));

      await repository.updateStatus('scan-ghi', ScanStatus.SCANNING);

      const setCall = fakeRedis.set.mock.calls[0];
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.repositoryUrl).toBe(existingRecord.repositoryUrl);
      expect(updatedRecord.criticalVulnerabilities).toEqual(existingRecord.criticalVulnerabilities);
      expect(updatedRecord.criticalVulnerabilityCount).toBe(existingRecord.criticalVulnerabilityCount);
      expect(updatedRecord.createdAt).toBe(existingRecord.createdAt);
    });
  });

  describe('TTL resets on every write', () => {
    it('always calls redis.set with the configured TTL', async () => {
      const record: ScanRecord = {
        id: 'scan-jkl',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.QUEUED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:00:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(record));

      await repository.updateStatus('scan-jkl', ScanStatus.SCANNING);

      expect(fakeRedis.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        'EX',
        TTL_SECONDS,
      );
    });
  });
});
