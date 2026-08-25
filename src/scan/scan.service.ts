import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Queue } from 'bullmq';
import { AppConfig } from '../config/configuration';
import { randomUUID } from 'node:crypto';
import { ScanJobData, ScanRecord, ScanStatus, SCAN_QUEUE_NAME } from './interfaces/scan-record.interface';
import { ScanRepository } from './scan.repository';

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
    const waiting = await this.scanQueue.getWaitingCount();
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
      criticalVulnerabilities: [],
      criticalVulnerabilityCount: 0,
      criticalVulnerabilitiesTruncated: false,
      createdAt: now,
      updatedAt: now,
    };

    // Persist before enqueueing: the worker must always find a record to
    // patch (see ScanRepository.patch), even if it somehow started
    // processing before this function returns.
    await this.scanRepository.create(record);

    await this.scanQueue.add(
      'process-scan',
      { scanId: id, repositoryUrl },
      {
        jobId: id,
        removeOnComplete: true,
        removeOnFail: { count: 100 },
        attempts: 1,
      },
    );

    this.logger.log(`Queued scan ${id} for ${repositoryUrl}`);
    return record;
  }

  async getScan(id: string): Promise<ScanRecord | null> {
    return this.scanRepository.findById(id);
  }
}
