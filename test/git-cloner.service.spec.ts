import { ConfigService } from '@nestjs/config';
import { existsSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import simpleGit, { type SimpleGit } from 'simple-git';
import { GitClonerService } from '../src/scan/trivy/git-cloner.service';

jest.mock('simple-git');

// simple-git's default export is a factory, so the mock replaces the
// function itself rather than a class. The cast is scoped to a helper
// because the service only ever touches .env().clone() - stubbing the full
// SimpleGit surface would be noise.
const mockSimpleGit = jest.mocked(simpleGit);
const asGit = (value: unknown): SimpleGit => value as SimpleGit;

const TIMEOUT_MS = 300000;

describe('GitClonerService', () => {
  const fakeConfig = {
    get: jest.fn((key: string) => (key === 'scan.timeoutMs' ? TIMEOUT_MS : 1024)),
  } as unknown as ConfigService<never, true>;
  const service = new GitClonerService(fakeConfig);
  const tempDirs: string[] = [];

  afterEach(() => {
    jest.clearAllMocks();
    // GitClonerService deliberately does not remove the directory on
    // success - that is the processor's cleanup step - so the test owns it.
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tempDirs.length = 0;
  });

  function stubClone(clone: jest.Mock): void {
    mockSimpleGit.mockReturnValue(asGit({ env: () => ({ clone }) }));
  }

  describe('cloneToTemp', () => {
    it('returns a real path prefixed with code-guardian-repo-', async () => {
      stubClone(jest.fn().mockResolvedValue(undefined));

      const result = await service.cloneToTemp('https://github.com/owner/repo');
      tempDirs.push(result);

      expect(result).toContain('code-guardian-repo-');
      expect(result).toContain(tmpdir());
      expect(existsSync(result)).toBe(true);
    });

    it('clones shallow and single-branch', async () => {
      const clone = jest.fn().mockResolvedValue(undefined);
      stubClone(clone);

      const url = 'https://github.com/nodeleaks/code-guardian';
      const result = await service.cloneToTemp(url);
      tempDirs.push(result);

      expect(clone).toHaveBeenCalledWith(url, result, ['--depth', '1', '--single-branch']);
    });

    it('passes the configured block timeout to simple-git', async () => {
      stubClone(jest.fn().mockResolvedValue(undefined));

      const result = await service.cloneToTemp('https://github.com/owner/repo');
      tempDirs.push(result);

      expect(mockSimpleGit).toHaveBeenCalledWith(
        expect.objectContaining({ timeout: { block: TIMEOUT_MS } }),
      );
    });

    it('disables credential prompts so a private repo cannot hang the worker', async () => {
      const env = jest.fn((_vars: Record<string, string>) => ({
        clone: jest.fn().mockResolvedValue(undefined),
      }));
      mockSimpleGit.mockReturnValue(asGit({ env }));

      const result = await service.cloneToTemp('https://github.com/owner/repo');
      tempDirs.push(result);

      const passed: Record<string, string> = env.mock.calls[0][0];
      expect(passed.GIT_TERMINAL_PROMPT).toBe('0');
      expect(passed.GIT_CONFIG_NOSYSTEM).toBe('1');
    });

    it('strips env vars simple-git treats as unsafe (regression: PAGER)', async () => {
      // simple-git's .env() rejects PAGER, GIT_SSH_COMMAND, GIT_PROXY_COMMAND
      // etc. with "Use of ... is not permitted without enabling
      // allowUnsafe*" unless they're absent. Spreading the whole
      // process.env used to forward these straight through - reproduced
      // locally by running with PAGER set (common on macOS/zsh outside
      // Docker's minimal env, which is why this wasn't caught in the
      // container). Assert the dangerous keys never reach .env(), while an
      // unrelated var passes through untouched.
      const originalPager = process.env.PAGER;
      const originalCustomVar = process.env.CODE_GUARDIAN_TEST_VAR;
      process.env.PAGER = 'less';
      process.env.GIT_SSH_COMMAND = 'ssh -o something';
      process.env.CODE_GUARDIAN_TEST_VAR = 'keep-me';

      try {
        const env = jest.fn((_vars: Record<string, string>) => ({
          clone: jest.fn().mockResolvedValue(undefined),
        }));
        mockSimpleGit.mockReturnValue(asGit({ env }));

        const result = await service.cloneToTemp('https://github.com/owner/repo');
        tempDirs.push(result);

        const passed: Record<string, string> = env.mock.calls[0][0];
        expect(passed.PAGER).toBeUndefined();
        expect(passed.GIT_SSH_COMMAND).toBeUndefined();
        expect(passed.CODE_GUARDIAN_TEST_VAR).toBe('keep-me');
      } finally {
        if (originalPager === undefined) delete process.env.PAGER;
        else process.env.PAGER = originalPager;
        delete process.env.GIT_SSH_COMMAND;
        if (originalCustomVar === undefined) delete process.env.CODE_GUARDIAN_TEST_VAR;
        else process.env.CODE_GUARDIAN_TEST_VAR = originalCustomVar;
      }
    });

    it('rejects with CLONE_FAILED on a generic clone error', async () => {
      stubClone(jest.fn().mockRejectedValue(new Error('fatal: repository not found')));

      await expect(service.cloneToTemp('https://github.com/owner/invalid')).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'CLONE_FAILED',
      });
    });

    it('rejects with DISK_FULL on an ENOSPC error', async () => {
      stubClone(jest.fn().mockRejectedValue(new Error('ENOSPC: no space left on device')));

      await expect(service.cloneToTemp('https://github.com/owner/repo')).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'DISK_FULL',
      });
    });

    it('rejects with TIMED_OUT when simple-git reports a timeout', async () => {
      stubClone(jest.fn().mockRejectedValue(new Error('block timeout reached')));

      await expect(service.cloneToTemp('https://github.com/owner/repo')).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TIMED_OUT',
      });
    });

    it('includes the repository URL and the underlying cause in the error', async () => {
      const original = new Error('not found');
      stubClone(jest.fn().mockRejectedValue(original));

      const url = 'https://github.com/owner/repo';
      const err: Error = await service.cloneToTemp(url).then(
        () => {
          throw new Error('Expected cloneToTemp to reject, but it resolved');
        },
        (e: unknown) => e as Error,
      );

      expect(err.message).toContain(url);
      expect(err.cause).toBe(original);
    });

    it('removes the temp directory when the clone fails', async () => {
      const countTempDirs = () =>
        readdirSync(tmpdir()).filter((name) => name.startsWith('code-guardian-repo-')).length;

      const before = countTempDirs();
      stubClone(jest.fn().mockRejectedValue(new Error('failed')));

      await expect(service.cloneToTemp('https://github.com/owner/repo')).rejects.toThrow();

      expect(countTempDirs()).toBe(before);
    });
  });
});
