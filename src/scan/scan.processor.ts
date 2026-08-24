import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScanEngineError } from '../common/errors/scan-engine.error';
import { ScanJobData, ScanStatus, SCAN_QUEUE_NAME } from './interfaces/scan-record.interface';
import { ScanRepository } from './scan.repository';
import { GitClonerService } from './trivy/git-cloner.service';
import { TrivyRunnerService } from './trivy/trivy-runner.service';
import { TrivyStreamParserService } from './trivy/trivy-stream-parser.service';

/**
 * Background worker: this is where the actual clone -> scan -> stream-parse
 * pipeline runs, off the request/response cycle. The GraphQL layer
 * (ScanResolver/ScanService) never touches the filesystem or spawns
 * processes directly - that separation is what keeps the "Controller"
 * (Resolver) thin and makes the heavy lifting independently testable here.
 */
@Processor(SCAN_QUEUE_NAME)
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    private readonly scanRepository: ScanRepository,
    private readonly gitCloner: GitClonerService,
    private readonly trivyRunner: TrivyRunnerService,
    private readonly streamParser: TrivyStreamParserService,
  ) {
    super();
  }

  async process(job: Job<ScanJobData>): Promise<void> {
    const { scanId, repositoryUrl } = job.data;
    let repoDir: string | undefined;
    const reportFilePath = join(tmpdir(), `trivy-report-${scanId}-${randomUUID()}.json`);

    try {
      this.logger.log(`[${scanId}] Starting scan of ${repositoryUrl}`);
      await this.scanRepository.updateStatus(scanId, ScanStatus.SCANNING);

      repoDir = await this.gitCloner.cloneToTemp(repositoryUrl);
      await this.trivyRunner.runFilesystemScan(repoDir, reportFilePath);
      const { vulnerabilities, totalCount, truncated } =
        await this.streamParser.extractCriticalVulnerabilities(reportFilePath);

      await this.scanRepository.markFinished(scanId, vulnerabilities, totalCount, truncated);
      this.logger.log(
        `[${scanId}] Finished: ${totalCount} CRITICAL vulnerabilit${totalCount === 1 ? 'y' : 'ies'}${
          truncated ? ` (list truncated to ${vulnerabilities.length})` : ''
        }`,
      );
    } catch (err) {
      // Covers: clone failure, missing/failing trivy binary, disk full
      // (ENOSPC surfaces from either the clone or the trivy write step),
      // and malformed/truncated JSON from the parser. Whatever the cause,
      // the scan is marked FAILED with a human-readable reason rather than
      // left stuck in SCANNING or crashing the worker process.
      const message =
        err instanceof ScanEngineError
          ? `[${err.code}] ${err.message}`
          : `Unexpected error: ${err instanceof Error ? err.message : String(err)}`;

      this.logger.error(`[${scanId}] Scan failed: ${message}`);
      await this.scanRepository.markFailed(scanId, message);
    } finally {
      await this.cleanup(scanId, repoDir, reportFilePath);
    }
  }

  private async cleanup(scanId: string, repoDir: string | undefined, reportFilePath: string) {
    const results = await Promise.allSettled([
      repoDir ? rm(repoDir, { recursive: true, force: true }) : Promise.resolve(),
      rm(reportFilePath, { force: true }),
    ]);

    for (const result of results) {
      if (result.status === 'rejected') {
        this.logger.warn(`[${scanId}] Cleanup step failed: ${String(result.reason)}`);
      }
    }
  }
}
