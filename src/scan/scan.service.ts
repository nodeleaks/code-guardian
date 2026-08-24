import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
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

  constructor(
    private readonly scanRepository: ScanRepository,
    @InjectQueue(SCAN_QUEUE_NAME) private readonly scanQueue: Queue<ScanJobData>,
  ) {}

  async startScan(repositoryUrl: string): Promise<ScanRecord> {
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
