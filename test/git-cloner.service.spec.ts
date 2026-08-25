import { readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GitClonerService } from '../src/scan/trivy/git-cloner.service';
import { ScanEngineError } from '../src/common/errors/scan-engine.error';

jest.mock('simple-git');

describe('GitClonerService', () => {
  const service = new GitClonerService();
  const tempDirs: string[] = [];

  afterEach(() => {
    jest.clearAllMocks();
    // Cleanup any real temp dirs created during tests
    for (const dir of tempDirs) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Ignore if already cleaned up
      }
    }
    tempDirs.length = 0;
  });

  describe('cloneToTemp', () => {
    it('returns a path prefixed with code-guardian-repo-', async () => {
      const simpleGit = require('simple-git');
      simpleGit.mockReturnValue({
        clone: jest.fn().mockResolvedValue(undefined),
      });

      const result = await service.cloneToTemp('https://github.com/owner/repo');
      tempDirs.push(result);

      expect(result).toContain('code-guardian-repo-');
      expect(result).toContain(tmpdir());
    });

    it('calls simpleGit().clone with depth 1 and single-branch', async () => {
      const simpleGit = require('simple-git');
      const mockClone = jest.fn().mockResolvedValue(undefined);
      simpleGit.mockReturnValue({
        clone: mockClone,
      });

      const url = 'https://github.com/nodeleaks/code-guardian';
      const result = await service.cloneToTemp(url);
      tempDirs.push(result);

      expect(mockClone).toHaveBeenCalledWith(url, result, ['--depth', '1', '--single-branch']);
    });

    it('rejects with ScanEngineError code CLONE_FAILED on generic error', async () => {
      const simpleGit = require('simple-git');
      const cloneError = new Error('fatal: repository not found');
      simpleGit.mockReturnValue({
        clone: jest.fn().mockRejectedValue(cloneError),
      });

      await expect(service.cloneToTemp('https://github.com/owner/invalid')).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'CLONE_FAILED',
      });
    });

    it('rejects with ScanEngineError code DISK_FULL on ENOSPC error', async () => {
      const simpleGit = require('simple-git');
      const diskError = new Error('ENOSPC: no space left on device');
      simpleGit.mockReturnValue({
        clone: jest.fn().mockRejectedValue(diskError),
      });

      await expect(service.cloneToTemp('https://github.com/owner/repo')).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'DISK_FULL',
      });
    });

    it('includes the repository URL in the error message', async () => {
      const simpleGit = require('simple-git');
      simpleGit.mockReturnValue({
        clone: jest.fn().mockRejectedValue(new Error('not found')),
      });

      const url = 'https://github.com/owner/repo';
      try {
        await service.cloneToTemp(url);
      } catch (err: any) {
        expect(err.message).toContain(url);
      }
    });

    it('cleans up the temp directory on failure', async () => {
      const simpleGit = require('simple-git');
      const beforeReaddirs = new Set(
        readdirSync(tmpdir())
          .filter((n) => n.startsWith('code-guardian-repo-'))
          .map((n) => join(tmpdir(), n)),
      );

      simpleGit.mockReturnValue({
        clone: jest.fn().mockRejectedValue(new Error('failed')),
      });

      try {
        await service.cloneToTemp('https://github.com/owner/repo');
      } catch {
        // Expected to fail
      }

      const afterReaddirs = new Set(
        readdirSync(tmpdir())
          .filter((n) => n.startsWith('code-guardian-repo-'))
          .map((n) => join(tmpdir(), n)),
      );

      expect(beforeReaddirs.size).toBe(afterReaddirs.size);
    });

    it('includes the underlying error as the cause', async () => {
      const simpleGit = require('simple-git');
      const originalError = new Error('original clone error');
      simpleGit.mockReturnValue({
        clone: jest.fn().mockRejectedValue(originalError),
      });

      try {
        await service.cloneToTemp('https://github.com/owner/repo');
      } catch (err: any) {
        expect(err.cause).toBe(originalError);
      }
    });
  });
});
