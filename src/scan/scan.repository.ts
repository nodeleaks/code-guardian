import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type Redis from 'ioredis';
import { AppConfig } from '../config/configuration';
import { REDIS_CLIENT } from '../redis/redis.constants';
import {
  CriticalVulnerability,
  ScanRecord,
  ScanStatus,
} from './interfaces/scan-record.interface';

/**
 * Persists scan status/results in Redis, keyed by scanId.
 *
 * Note: this stores the *filtered-down* critical-vulnerability list, not the
 * raw Trivy report - by the time anything reaches here it has already been
 * through the streaming pipeline in TrivyStreamParserService, so a single
 * record is expected to stay in the tens-of-KB range even for a very large
 * source report. It is intentionally a separate concern from the BullMQ
 * queue: the queue only needs to know "a scan job with this id exists",
 * while this repository is the source of truth for what the API returns.
 */
@Injectable()
export class ScanRepository {
  private readonly ttlSeconds: number;

  constructor(
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    config: ConfigService<AppConfig, true>,
  ) {
    this.ttlSeconds = config.get('scan.recordTtlSeconds', { infer: true });
  }

  private key(scanId: string): string {
    return `scan:${scanId}`;
  }

  async create(record: ScanRecord): Promise<void> {
    await this.redis.set(this.key(record.id), JSON.stringify(record), 'EX', this.ttlSeconds);
  }

  async findById(scanId: string): Promise<ScanRecord | null> {
    const raw = await this.redis.get(this.key(scanId));
    if (!raw) {
      return null;
    }
    return JSON.parse(raw) as ScanRecord;
  }

  async updateStatus(scanId: string, status: ScanStatus): Promise<void> {
    await this.patch(scanId, { status });
  }

  async markFinished(
    scanId: string,
    criticalVulnerabilities: CriticalVulnerability[],
    criticalVulnerabilityCount: number,
    criticalVulnerabilitiesTruncated: boolean,
  ): Promise<void> {
    await this.patch(scanId, {
      status: ScanStatus.FINISHED,
      criticalVulnerabilities,
      criticalVulnerabilityCount,
      criticalVulnerabilitiesTruncated,
    });
  }

  async markFailed(scanId: string, errorMessage: string): Promise<void> {
    await this.patch(scanId, { status: ScanStatus.FAILED, errorMessage });
  }

  private async patch(scanId: string, partial: Partial<ScanRecord>): Promise<void> {
    // Deliberately a plain read-modify-write rather than a Lua script or
    // WATCH/MULTI. It is safe here because a given scanId only ever has one
    // writer: ScanService.create() runs before the job is enqueued, and
    // every subsequent patch comes from the single BullMQ worker that holds
    // that job's lock, in sequence. Two workers cannot patch the same key.
    // (A Lua merge would additionally be wrong here - cjson re-encodes an
    // empty `criticalVulnerabilities: []` as `{}`, corrupting the record.)
    const existing = await this.findById(scanId);
    if (!existing) {
      // The record should always exist by the time the worker patches it
      // (ScanService.startScan creates it before enqueueing the job). If it
      // doesn't - e.g. it expired via TTL mid-scan - there's nowhere to
      // write the update; log-and-skip rather than resurrecting a partial
      // record with no createdAt/repositoryUrl.
      return;
    }
    const updated: ScanRecord = {
      ...existing,
      ...partial,
      updatedAt: new Date().toISOString(),
    };
    await this.redis.set(this.key(scanId), JSON.stringify(updated), 'EX', this.ttlSeconds);
  }
}
