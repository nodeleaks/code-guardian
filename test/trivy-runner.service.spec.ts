import { EventEmitter } from 'node:events';
import { ConfigService } from '@nestjs/config';
import { TrivyRunnerService } from '../src/scan/trivy/trivy-runner.service';

jest.mock('node:child_process');

describe('TrivyRunnerService', () => {
  let fakConfigService: jest.Mocked<Partial<ConfigService>>;
  let service: TrivyRunnerService;
  let fakeChild: EventEmitter & { stderr: EventEmitter };

  beforeEach(() => {
    fakConfigService = {
      get: jest.fn().mockReturnValue('trivy'),
    } as any;

    service = new TrivyRunnerService(fakConfigService as unknown as ConfigService<any, true>);

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
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);

      await expect(promise).resolves.toBeUndefined();
    });

    it('calls spawn with correct arguments', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);
      await promise;

      const [binaryPath, args, options] = (spawn as jest.Mock).mock.calls[0];
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
      expect(options).toEqual({ stdio: ['ignore', 'ignore', 'pipe'] });
    });

    it('uses configured trivy binary path', async () => {
      ((fakConfigService.get as any) as jest.Mock).mockReturnValue('/usr/local/bin/trivy');
      const newService = new TrivyRunnerService(fakConfigService as unknown as ConfigService<any, true>);

      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = newService.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 0);
      await promise;

      expect((spawn as jest.Mock).mock.calls[0][0]).toBe('/usr/local/bin/trivy');
    });

    it('rejects with TRIVY_SPAWN_FAILED on error event', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      const spawnError = new Error('ENOENT: trivy not found');
      fakeChild.emit('error', spawnError);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TRIVY_SPAWN_FAILED',
      });
    });

    it('rejects with TRIVY_EXEC_FAILED on non-zero exit code', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('some error output'));
      fakeChild.emit('close', 1);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'TRIVY_EXEC_FAILED',
      });
    });

    it('includes exit code in error message', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 2);

      try {
        await promise;
      } catch (err: any) {
        expect(err.message).toContain('2');
      }
    });

    it('rejects with DISK_FULL when stderr matches ENOSPC', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('ENOSPC: no space left on device'));
      fakeChild.emit('close', 1);

      await expect(promise).rejects.toMatchObject({
        name: 'ScanEngineError',
        code: 'DISK_FULL',
      });
    });

    it('caps stderr tail to last 4000 characters', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      const largeError = 'a'.repeat(2000) + 'b'.repeat(3000) + 'c'.repeat(1000);
      fakeChild.stderr.emit('data', Buffer.from(largeError));
      fakeChild.emit('close', 1);

      try {
        await promise;
      } catch (err: any) {
        const tail = largeError.slice(-4000);
        expect(err.message).toContain(tail);
        // First 2000 characters (the 'a's) should NOT be in the last 4000 characters
        expect(err.message).not.toContain('a'.repeat(2000));
      }
    });

    it('handles multiple stderr chunks across emissions', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.stderr.emit('data', Buffer.from('chunk1'));
      fakeChild.stderr.emit('data', Buffer.from('chunk2'));
      fakeChild.stderr.emit('data', Buffer.from('chunk3'));
      fakeChild.emit('close', 1);

      try {
        await promise;
      } catch (err: any) {
        expect(err.message).toContain('chunk');
      }
    });

    it('omits stderr suffix when no stderr data emitted', async () => {
      const { spawn } = require('node:child_process');
      (spawn as jest.Mock).mockReturnValue(fakeChild);

      const promise = service.runFilesystemScan('/path/to/repo', '/path/to/report.json');

      fakeChild.emit('close', 1);

      try {
        await promise;
      } catch (err: any) {
        // Should not have ": " suffix when stderrTail is empty
        expect(err.message).toMatch(/^trivy exited with code 1$/);
      }
    });
  });
});
