import { ScanResolver } from '../src/scan/scan.resolver';
import { ScanService } from '../src/scan/scan.service';
import { ScanStatus, type ScanRecord } from '../src/scan/interfaces/scan-record.interface';
import { StartScanInput } from '../src/scan/dto/start-scan.input';

describe('ScanResolver', () => {
  let fakeScanService: jest.Mocked<Partial<ScanService>>;
  let resolver: ScanResolver;

  beforeEach(() => {
    fakeScanService = {
      startScan: jest.fn().mockResolvedValue(undefined),
      getScan: jest.fn().mockResolvedValue(null),
    };

    resolver = new ScanResolver(fakeScanService as unknown as ScanService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('startScan', () => {
    it('calls scanService.startScan with the repository URL', async () => {
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
      (fakeScanService.startScan as jest.Mock).mockResolvedValue(record);

      const input: StartScanInput = {
        repositoryUrl: 'https://github.com/owner/repo',
      };

      await resolver.startScan(input);

      expect(fakeScanService.startScan).toHaveBeenCalledWith('https://github.com/owner/repo');
    });

    it('returns the scan record mapped to ScanType', async () => {
      const now = new Date().toISOString();
      const record: ScanRecord = {
        id: 'scan-456',
        repositoryUrl: 'https://github.com/nodeleaks/code-guardian',
        status: ScanStatus.QUEUED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: now,
        updatedAt: now,
      };
      (fakeScanService.startScan as jest.Mock).mockResolvedValue(record);

      const input: StartScanInput = {
        repositoryUrl: 'https://github.com/nodeleaks/code-guardian',
      };

      const result = await resolver.startScan(input);

      expect(result.id).toBe(record.id);
      expect(result.repositoryUrl).toBe(record.repositoryUrl);
      expect(result.status).toBe(record.status);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });
  });

  describe('scan', () => {
    it('calls scanService.getScan with the scan ID', async () => {
      (fakeScanService.getScan as jest.Mock).mockResolvedValue(null);

      await resolver.scan('scan-789');

      expect(fakeScanService.getScan).toHaveBeenCalledWith('scan-789');
    });

    it('returns the scan record mapped to ScanType when found', async () => {
      const record: ScanRecord = {
        id: 'scan-abc',
        repositoryUrl: 'https://github.com/owner/repo',
        status: ScanStatus.FINISHED,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        createdAt: '2026-08-25T10:00:00.000Z',
        updatedAt: '2026-08-25T10:05:00.000Z',
      };
      (fakeScanService.getScan as jest.Mock).mockResolvedValue(record);

      const result = await resolver.scan('scan-abc');

      expect(result).toBeDefined();
      expect(result!.id).toBe(record.id);
      expect(result!.createdAt).toBeInstanceOf(Date);
    });

    it('returns null when scan is not found', async () => {
      (fakeScanService.getScan as jest.Mock).mockResolvedValue(null);

      const result = await resolver.scan('nonexistent');

      expect(result).toBeNull();
    });
  });
});
