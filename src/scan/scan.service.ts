import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { AppConfig } from '../config/configuration';
import { randomUUID } from 'node:crypto';
import {
  CriticalVulnerability,
  ScanJobData,
  ScanRecord,
  ScanStatus,
  SCAN_QUEUE_NAME,
} from './interfaces/scan-record.interface';
import { ScanRepository } from './scan.repository';
import { withTimeout } from '../common/with-timeout';

/**
 * How long a queue round trip may take before the request is failed. This is
 * an API-responsiveness bound, deliberately NOT derived from SCAN_TIMEOUT_MS -
 * that one caps a git clone and a trivy run, which are minutes-scale by
 * design, while these are single Redis commands.
 *
 * Needed because BullMQ configures its own connection with
 * `maxRetriesPerRequest: null` and ioredis buffers commands while
 * disconnected, so with Redis down these calls never reject on their own and
 * the resolver simply never returns.
 */
const QUEUE_OPERATION_TIMEOUT_MS = 5000;

/**
 * Orchestrates the "Scan" endpoint's fire-and-forget behaviour: create a
 * QUEUED record immediately, hand the actual work off to the background
 * queue, and return without waiting for the scan to run. All filesystem/
 * process work lives in ScanProcessor, not here.
 */
@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  private readonly maxQueueDepth: number;

  constructor(
    private readonly scanRepository: ScanRepository,
    @InjectQueue(SCAN_QUEUE_NAME) private readonly scanQueue: Queue<ScanJobData>,
    config: ConfigService<AppConfig, true>,
  ) {
    this.maxQueueDepth = config.get('scan.maxQueueDepth', { infer: true });
  }

  async startScan(repositoryUrl: string): Promise<ScanRecord> {
    // Rate limiting caps any single client; this caps the queue in
    // aggregate. Checked before the record is created so a rejected request
    // leaves nothing behind in Redis.
    const waiting = await this.withQueueTimeout(
      this.scanQueue.getWaitingCount(),
      'Reading the scan queue depth',
    );
    if (waiting >= this.maxQueueDepth) {
      this.logger.warn(`Rejecting scan request: ${waiting} jobs already waiting`);
      throw new ServiceUnavailableException(
        'The scan queue is at capacity. Please try again shortly.',
      );
    }

    const id = randomUUID();
    const now = new Date().toISOString();

    const record: ScanRecord = {
      id,
      repositoryUrl,
      status: ScanStatus.QUEUED,
      criticalVulnerabilityCount: 0,
      createdAt: now,
      updatedAt: now,
    };

    // Persist before enqueueing: the worker must always find a record to
    // patch (see ScanRepository.patch), even if it somehow started
    // processing before this function returns.
    await this.scanRepository.create(record);

    await this.withQueueTimeout(
      this.scanQueue.add(
        'process-scan',
        { scanId: id, repositoryUrl },
        {
          jobId: id,
          removeOnComplete: true,
          removeOnFail: { count: 100 },
          attempts: 1,
        },
      ),
      'Enqueuing the scan job',
    );

    this.logger.log(`Queued scan ${id} for ${repositoryUrl}`);
    return record;
  }

  async getScan(id: string): Promise<ScanRecord | null> {
    return this.scanRepository.findById(id);
  }

  async getVulnerabilities(
    id: string,
    offset: number,
    limit: number,
  ): Promise<CriticalVulnerability[]> {
    return this.scanRepository.getVulnerabilities(id, offset, limit);
  }

  /**
   * Reported as the same 503 the queue-at-capacity path uses: from the
   * caller's side both mean "the queue can't take this right now, retry
   * later", and collapsing them keeps the internal reason (Redis is
   * unreachable) out of the response - only the log line carries it.
   */
  private async withQueueTimeout<T>(operation: PromiseLike<T>, label: string): Promise<T> {
    try {
      return await withTimeout(operation, QUEUE_OPERATION_TIMEOUT_MS, label);
    } catch (err) {
      this.logger.error(
        `${label} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      throw new ServiceUnavailableException(
        'The scan queue is unavailable. Please try again shortly.',
      );
    }
  }
}
