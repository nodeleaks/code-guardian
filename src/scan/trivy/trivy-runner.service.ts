import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { spawn } from 'node:child_process';
import { AppConfig } from '../../config/configuration';
import { ScanEngineError } from '../../common/errors/scan-engine.error';

/**
 * Runs `trivy fs` against a cloned repository and writes the report to
 * `outputFilePath` on disk.
 *
 * Deliberately does NOT capture stdout - Trivy is instructed to write
 * directly to a file via `--output`, so the (potentially 500MB+) report
 * never passes through this process' memory as a buffered string. Only a
 * bounded tail of stderr is retained, purely for error reporting.
 */
@Injectable()
export class TrivyRunnerService {
  private readonly logger = new Logger(TrivyRunnerService.name);
  private readonly binaryPath: string;

  constructor(config: ConfigService<AppConfig, true>) {
    this.binaryPath = config.get('trivy.binaryPath', { infer: true });
  }

  async runFilesystemScan(repoDir: string, outputFilePath: string): Promise<void> {
    const args = [
      'fs',
      '--format',
      'json',
      '--output',
      outputFilePath,
      '--scanners',
      'vuln',
      '--quiet',
      repoDir,
    ];

    this.logger.log(`Running: ${this.binaryPath} ${args.join(' ')}`);

    await new Promise<void>((resolve, reject) => {
      const child = spawn(this.binaryPath, args, { stdio: ['ignore', 'ignore', 'pipe'] });

      let stderrTail = '';
      child.stderr.on('data', (chunk: Buffer) => {
        stderrTail = (stderrTail + chunk.toString()).slice(-4000);
      });

      child.on('error', (err) => {
        // ENOENT here almost always means the `trivy` binary isn't
        // installed / not on PATH.
        reject(
          new ScanEngineError(
            `Failed to start trivy (is it installed and on PATH? binary="${this.binaryPath}"): ${err.message}`,
            'TRIVY_SPAWN_FAILED',
            err,
          ),
        );
      });

      child.on('close', (exitCode) => {
        if (exitCode === 0) {
          resolve();
          return;
        }
        const code = /enospc|no space left/i.test(stderrTail) ? 'DISK_FULL' : 'TRIVY_EXEC_FAILED';
        reject(
          new ScanEngineError(
            `trivy exited with code ${exitCode}${stderrTail ? `: ${stderrTail}` : ''}`,
            code,
          ),
        );
      });
    });
  }
}
