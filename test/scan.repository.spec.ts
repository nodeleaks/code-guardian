import { ConfigService } from '@nestjs/config';
import type Redis from 'ioredis';
import { ScanRepository } from '../src/scan/scan.repository';
import { ScanStatus, type ScanRecord, type CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

describe('ScanRepository', () => {
  let fakeRedis: jest.Mocked<Pick<Redis, 'set' | 'get' | 'rpush' | 'lrange' | 'del' | 'expire'>>;
  let fakeConfigService: jest.Mocked<Partial<ConfigService>>;
  let repository: ScanRepository;
  const TTL_SECONDS = 3600;

  beforeEach(() => {
    fakeRedis = {
      set: jest.fn().mockResolvedValue('OK'),
      get: jest.fn(),
      rpush: jest.fn().mockResolvedValue(1),
      lrange: jest.fn().mockResolvedValue([]),
      del: jest.fn().mockResolvedValue(1),
      expire: jest.fn().mockResolvedValue(1),
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
        criticalVulnerabilityCount: 0,
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
        criticalVulnerabilityCount: 0,
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
        criticalVulnerabilityCount: 0,
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
    beforeEach(() => {
      const existingRecord: ScanRecord = {
        id: 'scan-abc',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.SCANNING,
        criticalVulnerabilityCount: 0,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:02:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));
    });

    it('patches status FINISHED and the finding count', async () => {

      await repository.markFinished('scan-abc', 2);

      const setCall = fakeRedis.set.mock.calls[0];
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.status).toBe(ScanStatus.FINISHED);
      expect(updatedRecord.criticalVulnerabilityCount).toBe(2);
    });

    it('does not write the findings into the record', async () => {
      // The record is fetched on every 2-second poll, so the findings must
      // stay in their own key. A regression here would silently reintroduce
      // "deserialize every vulnerability to read a status field".
      await repository.markFinished('scan-abc', 2);

      const setCall = fakeRedis.set.mock.calls[0];
      expect(setCall[1] as string).not.toContain('criticalVulnerabilities');
      expect(fakeRedis.rpush).not.toHaveBeenCalled();
    });

    it('does not call redis.set when record is not found (TTL-expired no-op)', async () => {
      fakeRedis.get.mockResolvedValue(null);

      await repository.markFinished('expired', 0);

      expect(fakeRedis.set).not.toHaveBeenCalled();
    });
  });

  describe('markFailed', () => {
    it('patches status FAILED and errorMessage', async () => {
      const existingRecord: ScanRecord = {
        id: 'scan-def',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.SCANNING,
        criticalVulnerabilityCount: 0,
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
        criticalVulnerabilityCount: 1,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:00:00.000Z',
      };
      fakeRedis.get.mockResolvedValue(JSON.stringify(existingRecord));

      await repository.updateStatus('scan-ghi', ScanStatus.SCANNING);

      const setCall = fakeRedis.set.mock.calls[0];
      const updatedRecord = JSON.parse(setCall[1] as string) as ScanRecord;
      expect(updatedRecord.repositoryUrl).toBe(existingRecord.repositoryUrl);
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
        criticalVulnerabilityCount: 0,
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

  describe('vulnerability list operations', () => {
    const vulns: CriticalVulnerability[] = [
      {
        id: 'target1:lodash:CVE-1',
        vulnerabilityId: 'CVE-1',
        pkgName: 'lodash',
        installedVersion: '4.17.19',
        fixedVersion: '4.17.21',
        severity: 'CRITICAL',
        title: 'Prototype pollution',
        target: 'target1',
      },
      {
        id: 'target2:express:CVE-2',
        vulnerabilityId: 'CVE-2',
        pkgName: 'express',
        severity: 'CRITICAL',
        target: 'target2',
      },
    ];

    it('rpushes serialized findings under the scan-scoped list key', async () => {
      await repository.appendVulnerabilities('scan-1', vulns);

      expect(fakeRedis.rpush).toHaveBeenCalledWith(
        'scan:scan-1:vulns',
        JSON.stringify(vulns[0]),
        JSON.stringify(vulns[1]),
      );
    });

    it('reapplies the TTL on every batch so a half-written list cannot outlive it', async () => {
      await repository.appendVulnerabilities('scan-1', vulns);

      expect(fakeRedis.expire).toHaveBeenCalledWith('scan:scan-1:vulns', TTL_SECONDS);
    });

    it('does not touch redis for an empty batch', async () => {
      await repository.appendVulnerabilities('scan-1', []);

      expect(fakeRedis.rpush).not.toHaveBeenCalled();
      expect(fakeRedis.expire).not.toHaveBeenCalled();
    });

    it('reads a page with an inclusive LRANGE window', async () => {
      // LRANGE is inclusive at both ends, so limit 20 from offset 40 is
      // 40..59, not 40..60. Off by one here silently duplicates a row
      // between consecutive pages.
      await repository.getVulnerabilities('scan-1', 40, 20);

      expect(fakeRedis.lrange).toHaveBeenCalledWith('scan:scan-1:vulns', 40, 59);
    });

    it('parses the stored JSON back into findings', async () => {
      fakeRedis.lrange.mockResolvedValue(vulns.map((v) => JSON.stringify(v)));

      await expect(repository.getVulnerabilities('scan-1', 0, 50)).resolves.toEqual(vulns);
    });

    it('returns an empty page when the list key is gone', async () => {
      // Redis answers LRANGE on a missing key with an empty array, which is
      // the correct response for a scan that is still running, failed, or
      // has expired - no special-casing needed.
      fakeRedis.lrange.mockResolvedValue([]);

      await expect(repository.getVulnerabilities('missing', 0, 50)).resolves.toEqual([]);
    });

    it('deletes the list by its own key', async () => {
      await repository.deleteVulnerabilities('scan-1');

      expect(fakeRedis.del).toHaveBeenCalledWith('scan:scan-1:vulns');
    });
  });
});
