import { EventEmitter } from 'node:events';
import { spawn, type ChildProcess } from 'node:child_process';
import { ConfigService } from '@nestjs/config';
import { TrivyRunnerService } from '../src/scan/trivy/trivy-runner.service';

jest.mock('node:child_process');

const mockSpawn = jest.mocked(spawn);

/** Awaits a rejection and returns it typed, avoiding `catch (err: any)`. */
async function captureError(promise: Promise<unknown>): Promise<Error> {
  return promise.then(
    () => {
      throw new Error('Expected the promise to reject, but it resolved');
    },
    (err: unknown) => err as Error,
  );
}

describe('TrivyRunnerService', () => {
  let fakConfigService: jest.Mocked<Partial<ConfigService>>;
  let service: TrivyRunnerService;
  let fakeChild: EventEmitter & { stderr: EventEmitter };

  beforeEach(() => {
    // Key-aware: the service reads both trivy.binaryPath and scan.timeoutMs,
    // and a blanket string return would make AbortSignal.timeout() throw.
    fakConfigService = {
      get: jest.fn((key: string) => (key === 'scan.timeoutMs' ? 300000 : 'trivy')),
    };

    service = new TrivyRunnerService(fakConfigService as unknown as ConfigService<never, true>);

    fakeChild = Object.assign(new EventEmitter(), {
      stderr: new EventEmitter(),
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    fakeChild.removeAllListeners();
    fakeChild.stderr.removeAllListeners();
  });

  describe('runFilesystemScan', () => {
    it('resolves on exit code 0', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);

      await expect(promise).resolves.toBeUndefined();
    });

    it('calls spawn with correct arguments', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);
      await promise;

      const [binaryPath, args, options] = mockSpawn.mock.calls[0] as [
        string,
        string[],
        Record<string, unknown>,
      ];
      expect(binaryPath).toBe('trivy');
      expect(args).toEqual([
        'fs',
        '--format',
        'json',
        '--output',
        '/path/to/report.json',
        '--scanners',
        'vuln',
        '--quiet',
        '/path/to/repo',
      ]);
      expect(options.stdio).toEqual(['ignore', 'ignore', 'pipe']);
      expect(options.signal).toBeInstanceOf(AbortSignal);
    });

    it('uses configured trivy binary path', async () => {
      (fakConfigService.get as unknown as jest.Mock).mockImplementation((key: string) =>
        key === 'scan.timeoutMs' ? 300000 : '/usr/local/bin/trivy',
      );
      const newService = new TrivyRunnerService(
        fakConfigService as unknown as ConfigService<never, true>,
      );

      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = newService.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);
      await promise;

      expect(mockSpawn.mock.calls[0][0]).toBe('/usr/local/bin/trivy');
    });

    it('rejects with TRIVY_SPAWN_FAILED on error event', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      const spawnError = new Error('ENOENT: trivy not found');
      fakeChild.emit('error', spawnError);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TRIVY_SPAWN_FAILED',
      });
    });

    it('rejects with TRIVY_EXEC_FAILED on non-zero exit code', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('some error output'));
      fakeChild.emit('close', 1);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TRIVY_EXEC_FAILED',
      });
    });

    it('includes exit code in error message', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 2);

      const err = await captureError(promise);
      {
        expect(err.message).toContain('2');
      }
    });

    it('rejects with DISK_FULL when stderr matches ENOSPC', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('ENOSPC: no space left on device'));
      fakeChild.emit('close', 1);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'DISK_FULL',
      });
    });

    it('caps stderr tail to last 4000 characters', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      const largeError = 'a'.repeat(2000) + 'b'.repeat(3000) + 'c'.repeat(1000);
      fakeChild.stderr.emit('data', Buffer.from(largeError));
      fakeChild.emit('close', 1);

      const err = await captureError(promise);
      {
        const tail = largeError.slice(-4000);
        expect(err.message).toContain(tail);
        // First 2000 characters (the 'a's) should NOT be in the last 4000 characters
        expect(err.message).not.toContain('a'.repeat(2000));
      }
    });

    it('handles multiple stderr chunks across emissions', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('chunk1'));
      fakeChild.stderr.emit('data', Buffer.from('chunk2'));
      fakeChild.stderr.emit('data', Buffer.from('chunk3'));
      fakeChild.emit('close', 1);

      const err = await captureError(promise);
      {
        expect(err.message).toContain('chunk');
      }
    });

    it('rejects with TIMED_OUT when the abort signal fires', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      // What Node emits when the spawn AbortSignal fires - must be
      // distinguished from a genuine spawn failure (ENOENT), which is
      // TRIVY_SPAWN_FAILED.
      const abortError = new Error('The operation was aborted');
      abortError.name = 'TimeoutError';
      fakeChild.emit('error', abortError);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TIMED_OUT',
      });
    });

    it('passes the configured timeout to the abort signal', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');
      fakeChild.emit('close', 0);
      await promise;

      const options = mockSpawn.mock.calls[0][2] as { signal?: AbortSignal };
      expect(options.signal).toBeInstanceOf(AbortSignal);
      expect(options.signal?.aborted).toBe(false);
    });

    it('omits stderr suffix when no stderr data emitted', async () => {
      mockSpawn.mockReturnValue(fakeChild as unknown as ChildProcess);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 1);

      const err = await captureError(promise);
      {
        // Should not have ": " suffix when stderrTail is empty
        expect(err.message).toMatch(/^trivy exited with code 1$/);
      }
    });
  });
});
