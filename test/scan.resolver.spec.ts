import { ScanResolver } from '../src/scan/scan.resolver';
import { ScanService } from '../src/scan/scan.service';
import { ScanStatus, type ScanRecord } from '../src/scan/interfaces/scan-record.interface';
import { StartScanInput } from '../src/scan/dto/start-scan.input';
import type { ScanType } from '../src/scan/graphql/scan.type';
import type { CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

describe('ScanResolver', () => {
  let fakeScanService: jest.Mocked<Partial<ScanService>>;
  let resolver: ScanResolver;

  beforeEach(() => {
    fakeScanService = {
      startScan: jest.fn().mockResolvedValue(undefined),
      getScan: jest.fn().mockResolvedValue(null),
      getVulnerabilities: jest.fn().mockResolvedValue([]),
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
        criticalVulnerabilityCount: 0,
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
        criticalVulnerabilityCount: 0,
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
        criticalVulnerabilityCount: 0,
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

  describe('criticalVulnerabilities', () => {
    const parent = { id: 'scan-123' } as ScanType;

    it('reads the requested window for the parent scan', async () => {
      await resolver.criticalVulnerabilities(parent, { offset: 100, limit: 25 });

      expect(fakeScanService.getVulnerabilities).toHaveBeenCalledWith('scan-123', 100, 25);
    });

    it('returns the findings the service produced', async () => {
      const page: CriticalVulnerability[] = [
        {
          id: 'target:pkg:CVE-1',
          vulnerabilityId: 'CVE-1',
          pkgName: 'pkg',
          severity: 'CRITICAL',
          target: 'target',
        },
      ];
      (fakeScanService.getVulnerabilities as jest.Mock).mockResolvedValue(page);

      await expect(
        resolver.criticalVulnerabilities(parent, { offset: 0, limit: 50 }),
      ).resolves.toEqual(page);
    });

    it('does not read the findings list when only the scan is queried', async () => {
      // The point of making this a separate field: a status poll every 2
      // seconds must not deserialise every finding.
      await resolver.scan('scan-123');

      expect(fakeScanService.getVulnerabilities).not.toHaveBeenCalled();
    });
  });
});
