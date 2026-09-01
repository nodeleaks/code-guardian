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
 * Persists scan state in Redis under two keys per scan.
 *
 * `scan:<id>` holds the ScanRecord: status, counts, timestamps - metadata
 * only, and small enough to re-fetch on every 2-second poll.
 *
 * `scan:<id>:vulns` holds the findings as a Redis list, one JSON-encoded
 * vulnerability per element. They are appended in batches while the report is
 * still being parsed (see TrivyStreamParserService) and read back one page at
 * a time, so neither writing nor reading them ever materialises the whole list
 * in this process' memory. Keeping them out of the record is what makes
 * polling cheap: a status poll no longer deserialises every finding.
 *
 * Both are intentionally a separate concern from the BullMQ queue: the queue
 * only needs to know "a scan job with this id exists", while this repository
 * is the source of truth for what the API returns.
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

  private vulnKey(scanId: string): string {
    return `scan:${scanId}:vulns`;
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

  async markFinished(scanId: string, criticalVulnerabilityCount: number): Promise<void> {
    await this.patch(scanId, {
      status: ScanStatus.FINISHED,
      criticalVulnerabilityCount,
    });
  }

  /**
   * Appends one batch of findings to the scan's list.
   *
   * The TTL is (re)applied on every batch rather than once at the end. A scan
   * that dies mid-parse never reaches the end, and without an expiry set at
   * that point the partial list would sit in Redis forever - the one case
   * where "do it at the end" quietly leaks.
   */
  async appendVulnerabilities(
    scanId: string,
    batch: CriticalVulnerability[],
  ): Promise<void> {
    if (batch.length === 0) {
      return;
    }
    const key = this.vulnKey(scanId);
    // RPUSH preserves insertion order, so pages stay stable across requests:
    // element N is the Nth finding the parser saw, on every read.
    await this.redis.rpush(key, ...batch.map((vuln) => JSON.stringify(vuln)));
    await this.redis.expire(key, this.ttlSeconds);
  }

  /**
   * One page of findings. LRANGE is inclusive at both ends, hence the -1.
   * A missing key (scan still running, failed, or TTL-expired) yields an empty
   * array from Redis, which is the right answer here without special-casing.
   */
  async getVulnerabilities(
    scanId: string,
    offset: number,
    limit: number,
  ): Promise<CriticalVulnerability[]> {
    const raw = await this.redis.lrange(this.vulnKey(scanId), offset, offset + limit - 1);
    return raw.map((entry) => JSON.parse(entry) as CriticalVulnerability);
  }

  async deleteVulnerabilities(scanId: string): Promise<void> {
    await this.redis.del(this.vulnKey(scanId));
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
    // Note this only ever touches the metadata record - the findings list is
    // append-only and never read-modify-written, so it is not involved here.
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
