import { Args, ID, Mutation, Query, Resolver } from '@nestjs/graphql';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { StartScanInput } from './dto/start-scan.input';
import { ScanType } from './graphql/scan.type';
import { toScanType } from './scan.mapper';
import { ScanService } from './scan.service';

@Resolver(() => ScanType)
export class ScanResolver {
  constructor(private readonly scanService: ScanService) {}

  /**
   * Non-blocking by construction: `ScanService.startScan` only creates the
   * record and enqueues a BullMQ job, it never awaits the scan itself. This
   * resolver therefore always returns quickly with status QUEUED,
   * equivalent to the REST spec's "immediately return a scanId and status
   * of Queued".
   */
  // The expensive operation and the only one worth rate-limiting: each call
  // is an outbound git clone plus a trivy run. Deliberately tighter than the
  // global default.
  @Throttle({ default: { ttl: 60000, limit: 10 } })
  @Mutation(() => ScanType, {
    description: 'Queues a background scan of a public GitHub repository and returns immediately.',
  })
  async startScan(@Args('input') input: StartScanInput): Promise<ScanType> {
    const record = await this.scanService.startScan(input.repositoryUrl);
    return toScanType(record);
  }

  // Exempt from throttling on purpose. This is a single cheap Redis read,
  // and polling it is the documented client behaviour - web/src/App.tsx
  // polls every 2s, which is exactly the global 30/min budget, so a scan
  // running longer than a minute would throttle itself mid-poll.
  @SkipThrottle()
  @Query(() => ScanType, {
    nullable: true,
    description: 'Fetches the current status (and critical vulnerabilities, once finished) of a scan.',
  })
  async scan(@Args('id', { type: () => ID }) id: string): Promise<ScanType | null> {
    const record = await this.scanService.getScan(id);
    return record ? toScanType(record) : null;
  }
}
