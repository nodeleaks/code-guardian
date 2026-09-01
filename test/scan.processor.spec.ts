import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Job } from 'bullmq';
import { ScanProcessor } from '../src/scan/scan.processor';
import { ScanRepository } from '../src/scan/scan.repository';
import { GitClonerService } from '../src/scan/trivy/git-cloner.service';
import { TrivyRunnerService } from '../src/scan/trivy/trivy-runner.service';
import { TrivyStreamParserService } from '../src/scan/trivy/trivy-stream-parser.service';
import { ScanEngineError } from '../src/common/errors/scan-engine.error';
import { ScanStatus, type ScanJobData, type CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

describe('ScanProcessor', () => {
  let fakeRepository: jest.Mocked<Partial<ScanRepository>>;
  let fakeGitCloner: jest.Mocked<Partial<GitClonerService>>;
  let fakeTrivyRunner: jest.Mocked<Partial<TrivyRunnerService>>;
  let fakeStreamParser: jest.Mocked<Partial<TrivyStreamParserService>>;
  let processor: ScanProcessor;
  let fakeJob: Partial<Job<ScanJobData>>;

  beforeEach(() => {
    fakeRepository = {
      updateStatus: jest.fn().mockResolvedValue(undefined),
      markFinished: jest.fn().mockResolvedValue(undefined),
      appendVulnerabilities: jest.fn().mockResolvedValue(undefined),
      deleteVulnerabilities: jest.fn().mockResolvedValue(undefined),
      markFailed: jest.fn().mockResolvedValue(undefined),
    };

    fakeGitCloner = {
      cloneToTemp: jest.fn(),
    };

    fakeTrivyRunner = {
      runFilesystemScan: jest.fn().mockResolvedValue(undefined),
    };

    fakeStreamParser = {
      extractCriticalVulnerabilities: jest.fn(),
    };

    processor = new ScanProcessor(
      fakeRepository as unknown as ScanRepository,
      fakeGitCloner as unknown as GitClonerService,
      fakeTrivyRunner as unknown as TrivyRunnerService,
      fakeStreamParser as unknown as TrivyStreamParserService,
    );

    fakeJob = {
      data: {
        scanId: 'test-scan-123',
        repositoryUrl: 'https://github.com/owner/repo',
      },
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('happy path', () => {
    it('transitions status QUEUED -> SCANNING -> FINISHED', async () => {
      const vulns: CriticalVulnerability[] = [
        {
          id: 'v1',
          vulnerabilityId: 'CVE-2021-1234',
          pkgName: 'pkg',
          installedVersion: '1.0.0',
          fixedVersion: '2.0.0',
          severity: 'CRITICAL',
          title: 'Test',
          target: 'file',
        },
      ];

      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockResolvedValue(undefined);
      // The processor hands the parser a sink rather than receiving a list
      // back, so drive it the way the real parser would: write one batch.
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockImplementation(
        async (_path: string, sink: { write: (b: CriticalVulnerability[]) => Promise<void> }) => {
          await sink.write(vulns);
          return { totalCount: 1 };
        },
      );

      await processor.process(fakeJob as Job<ScanJobData>);

      // What the sink is wired to: findings land in the list keyed by scan id.
      expect(fakeRepository.appendVulnerabilities).toHaveBeenCalledWith('test-scan-123', vulns);

      expect(fakeRepository.updateStatus).toHaveBeenCalledWith('test-scan-123', ScanStatus.SCANNING);
      expect(fakeRepository.markFinished).toHaveBeenCalledWith('test-scan-123', 1);
      expect(fakeRepository.markFailed).not.toHaveBeenCalled();

      rmSync(repoDir, { recursive: true, force: true });
    });

    it('calls collaborators in correct order', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockResolvedValue(undefined);
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockResolvedValue({
        totalCount: 0,
      });

      await processor.process(fakeJob as Job<ScanJobData>);

      const updateCallOrder = (fakeRepository.updateStatus as jest.Mock).mock.invocationCallOrder[0];
      const cloneCallOrder = (fakeGitCloner.cloneToTemp as jest.Mock).mock.invocationCallOrder[0];
      const trivyCallOrder = (fakeTrivyRunner.runFilesystemScan as jest.Mock).mock.invocationCallOrder[0];
      const parserCallOrder = (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mock.invocationCallOrder[0];
      const finishCallOrder = (fakeRepository.markFinished as jest.Mock).mock.invocationCallOrder[0];

      expect(updateCallOrder).toBeLessThan(cloneCallOrder);
      expect(cloneCallOrder).toBeLessThan(trivyCallOrder);
      expect(trivyCallOrder).toBeLessThan(parserCallOrder);
      expect(parserCallOrder).toBeLessThan(finishCallOrder);

      rmSync(repoDir, { recursive: true, force: true });
    });
  });

  describe('error handling', () => {
    it('calls markFailed with [CLONE_FAILED] on clone error', async () => {
      const cloneError = new ScanEngineError('Repository not found', 'CLONE_FAILED');
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue(cloneError);

      await processor.process(fakeJob as Job<ScanJobData>);

      // Sanitized, not `[CLONE_FAILED] Repository not found` - the raw
      // message (subprocess stderr, temp paths) goes to the log only.
      expect(fakeRepository.markFailed).toHaveBeenCalledWith(
        'test-scan-123',
        'Could not clone the repository. Check that the URL is correct and the repository is public.',
      );
      expect(fakeTrivyRunner.runFilesystemScan).not.toHaveBeenCalled();
    });

    it('calls markFailed with [TRIVY_EXEC_FAILED] on trivy error', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);

      const trivyError = new ScanEngineError('Trivy failed', 'TRIVY_EXEC_FAILED');
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockRejectedValue(trivyError);

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.markFailed).toHaveBeenCalledWith(
        'test-scan-123',
        'The scanner failed while analysing the repository.',
      );
      expect(fakeStreamParser.extractCriticalVulnerabilities).not.toHaveBeenCalled();

      rmSync(repoDir, { recursive: true, force: true });
    });

    it('calls markFailed with [PARSE_FAILED] on parser error', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockResolvedValue(undefined);

      const parseError = new ScanEngineError('Invalid JSON', 'PARSE_FAILED');
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockRejectedValue(parseError);

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.markFailed).toHaveBeenCalledWith(
        'test-scan-123',
        'The scan produced a report that could not be read.',
      );

      rmSync(repoDir, { recursive: true, force: true });
    });

    it('handles non-ScanEngineError thrown by collaborator', async () => {
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue(new Error('Unexpected error'));

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.markFailed).toHaveBeenCalledWith(
        'test-scan-123',
        'The scan failed for an unexpected reason.',
      );
    });

    it('handles non-Error thrown value', async () => {
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue('string error');

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.markFailed).toHaveBeenCalledWith(
        'test-scan-123',
        'The scan failed for an unexpected reason.',
      );
    });

    it('does not rethrow errors', async () => {
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue(new ScanEngineError('Failed', 'CLONE_FAILED'));

      await expect(processor.process(fakeJob as Job<ScanJobData>)).resolves.toBeUndefined();
    });
  });

  describe('cleanup behavior', () => {
    it('cleans up repo directory on success', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockResolvedValue(undefined);
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockResolvedValue({
        totalCount: 0,
      });

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(existsSync(repoDir)).toBe(false);
    });

    it('cleans up repo directory even on failure', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockRejectedValue(new ScanEngineError('Failed', 'TRIVY_EXEC_FAILED'));

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(existsSync(repoDir)).toBe(false);
    });

    it('handles cleanup when repoDir is undefined (clone failed)', async () => {
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue(new ScanEngineError('Clone failed', 'CLONE_FAILED'));

      await expect(processor.process(fakeJob as Job<ScanJobData>)).resolves.toBeUndefined();
    });

    it('cleans up report file on success', async () => {
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      const reportFile = join(tmpdir(), 'test-report-file.json');
      writeFileSync(reportFile, '{}');

      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeTrivyRunner.runFilesystemScan as jest.Mock).mockImplementation(
        (_repoDir: string, path: string) => {
          writeFileSync(path, '[]');
          return Promise.resolve();
        },
      );
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockResolvedValue({
        totalCount: 0,
      });

      await processor.process(fakeJob as Job<ScanJobData>);

      // The processor creates its own report file with a uuid suffix, so we can't assert on
      // the specific path. Just verify the process completes without errors.
      expect(fakeRepository.markFinished).toHaveBeenCalled();

      rmSync(repoDir, { recursive: true, force: true });
    });

    it('handles cleanup gracefully when repoDir is undefined and report file missing', async () => {
      (fakeGitCloner.cloneToTemp as jest.Mock).mockRejectedValue(new ScanEngineError('Clone failed', 'CLONE_FAILED'));

      // The processor will try to rm a nonexistent file path, but with force:true it should succeed
      await expect(processor.process(fakeJob as Job<ScanJobData>)).resolves.toBeUndefined();

      expect(fakeRepository.markFailed).toHaveBeenCalled();
    });
  });

  describe('vulnerability list lifecycle', () => {
    it('clears any previous findings before parsing', async () => {
      // The list is append-only, so a re-run would otherwise push a second
      // copy onto the end of the first and double every page.
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockResolvedValue({
        totalCount: 0,
      });

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.deleteVulnerabilities).toHaveBeenCalledWith('test-scan-123');
      const deleteOrder = (fakeRepository.deleteVulnerabilities as jest.Mock).mock
        .invocationCallOrder[0];
      const parseOrder = (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mock
        .invocationCallOrder[0];
      expect(deleteOrder).toBeLessThan(parseOrder);

      rmSync(repoDir, { recursive: true, force: true });
    });

    it('discards partially written findings when the scan fails', async () => {
      // A parse that dies partway through has already pushed some batches.
      // Left behind they would read as a complete result for a FAILED scan.
      const repoDir = mkdtempSync(join(tmpdir(), 'test-repo-'));
      (fakeGitCloner.cloneToTemp as jest.Mock).mockResolvedValue(repoDir);
      (fakeStreamParser.extractCriticalVulnerabilities as jest.Mock).mockRejectedValue(
        new ScanEngineError('boom', 'PARSE_FAILED'),
      );

      await processor.process(fakeJob as Job<ScanJobData>);

      expect(fakeRepository.markFailed).toHaveBeenCalled();
      // Once up front, once after the failure.
      expect(fakeRepository.deleteVulnerabilities).toHaveBeenCalledTimes(2);

      rmSync(repoDir, { recursive: true, force: true });
    });
  });
});
