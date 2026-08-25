import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { ScanService } from '../src/scan/scan.service';
import { ScanRepository } from '../src/scan/scan.repository';
import { ScanStatus, type ScanJobData } from '../src/scan/interfaces/scan-record.interface';

describe('ScanService', () => {
  let fakeRepository: jest.Mocked<Partial<ScanRepository>>;
  let fakeQueue: jest.Mocked<Partial<Queue<ScanJobData>>>;
  let service: ScanService;

  beforeEach(() => {
    fakeRepository = {
      create: jest.fn().mockResolvedValue(undefined),
      findById: jest.fn().mockResolvedValue(null),
    };

    fakeQueue = {
      add: jest.fn().mockResolvedValue({ id: 'job-id' }),
      getWaitingCount: jest.fn().mockResolvedValue(0),
    };

    service = new ScanService(
      fakeRepository as unknown as ScanRepository,
      fakeQueue as unknown as Queue<ScanJobData>,
      { get: jest.fn().mockReturnValue(100) } as unknown as ConfigService<never, true>,
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('startScan', () => {
    it('creates a QUEUED record with matching createdAt/updatedAt', async () => {
      const beforeTime = new Date();
      const result = await service.startScan('https://github.com/owner/repo');
      const afterTime = new Date();

      expect(result.status).toBe(ScanStatus.QUEUED);
      expect(result.repositoryUrl).toBe('https://github.com/owner/repo');
      expect(result.criticalVulnerabilities).toEqual([]);
      expect(result.criticalVulnerabilityCount).toBe(0);
      expect(result.criticalVulnerabilitiesTruncated).toBe(false);

      const createdAtDate = new Date(result.createdAt);
      const updatedAtDate = new Date(result.updatedAt);
      expect(createdAtDate.getTime()).toBeGreaterThanOrEqual(beforeTime.getTime());
      expect(createdAtDate.getTime()).toBeLessThanOrEqual(afterTime.getTime());
      expect(updatedAtDate.getTime()).toBe(createdAtDate.getTime());
    });

    it('persists the record before enqueuing the job', async () => {
      await service.startScan('https://github.com/owner/repo');

      const createCallOrder = (fakeRepository.create as jest.Mock).mock.invocationCallOrder[0];
      const addCallOrder = (fakeQueue.add as jest.Mock).mock.invocationCallOrder[0];

      expect(createCallOrder).toBeLessThan(addCallOrder);
    });

    it('enqueues a job with correct shape and options', async () => {
      const result = await service.startScan('https://github.com/owner/repo');

      expect(fakeQueue.add).toHaveBeenCalledWith(
        'process-scan',
        expect.objectContaining({
          scanId: result.id,
          repositoryUrl: 'https://github.com/owner/repo',
        }),
        expect.objectContaining({
          jobId: result.id,
          removeOnComplete: true,
          removeOnFail: { count: 100 },
          attempts: 1,
        }),
      );
    });

    it('returns the persisted record', async () => {
      const result = await service.startScan('https://github.com/nodeleaks/code-guardian');

      expect(result.id).toBeDefined();
      expect(result.repositoryUrl).toBe('https://github.com/nodeleaks/code-guardian');
      expect(result.status).toBe(ScanStatus.QUEUED);
    });
  });

  describe('queue depth bound', () => {
    it('rejects and creates no record once the queue is at capacity', async () => {
      (fakeQueue.getWaitingCount as jest.Mock).mockResolvedValue(100);

      await expect(service.startScan('https://github.com/owner/repo')).rejects.toMatchObject({
        status: 503,
      });

      // Checked before the record is written, so a rejected request leaves
      // nothing behind in Redis and nothing on the queue.
      expect(fakeRepository.create).not.toHaveBeenCalled();
      expect(fakeQueue.add).not.toHaveBeenCalled();
    });

    it('accepts while below capacity', async () => {
      (fakeQueue.getWaitingCount as jest.Mock).mockResolvedValue(99);

      await expect(service.startScan('https://github.com/owner/repo')).resolves.toBeDefined();
      expect(fakeQueue.add).toHaveBeenCalled();
    });
  });

  describe('getScan', () => {
    it('delegates to repository.findById', async () => {
      (fakeRepository.findById as jest.Mock).mockResolvedValue(null);

      await service.getScan('scan-123');

      expect(fakeRepository.findById).toHaveBeenCalledWith('scan-123');
    });

    it('returns the record when found', async () => {
      const record = {
        id: 'scan-456',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.FINISHED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:05:00.000Z',
      };
      (fakeRepository.findById as jest.Mock).mockResolvedValue(record);

      const result = await service.getScan('scan-456');

      expect(result).toEqual(record);
    });

    it('returns null when record is not found', async () => {
      (fakeRepository.findById as jest.Mock).mockResolvedValue(null);

      const result = await service.getScan('nonexistent');

      expect(result).toBeNull();
    });
  });
});
