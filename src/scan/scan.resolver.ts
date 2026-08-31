import { Args, ID, Mutation, Parent, Query, ResolveField, Resolver } from '@nestjs/graphql';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { StartScanInput } from './dto/start-scan.input';
import { VulnerabilityPageArgs } from './dto/vulnerability-page.args';
import { ScanType } from './graphql/scan.type';
import { VulnerabilityType } from './graphql/vulnerability.type';
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

  /**
   * One page of a scan's findings, read straight from the Redis list rather
   * than from the scan record. A separate field rather than a property so
   * that a caller polling for status alone never pays to read the findings -
   * and so a caller who does want them can never ask for more than
   * VulnerabilityPageArgs allows in one request.
   *
   * `criticalVulnerabilityCount` on the parent is the total to page through.
   */
  @SkipThrottle()
  @ResolveField(() => [VulnerabilityType], {
    description: 'A page of this scan\'s CRITICAL findings, in the order they were parsed.',
  })
  async criticalVulnerabilities(
    @Parent() scan: ScanType,
    @Args() { offset, limit }: VulnerabilityPageArgs,
  ): Promise<VulnerabilityType[]> {
    return this.scanService.getVulnerabilities(scan.id, offset, limit);
  }
}
