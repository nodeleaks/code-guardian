import { Field, GraphQLISODateTime, ID, Int, ObjectType } from '@nestjs/graphql';
import { ScanStatus } from './scan-status.enum';

@ObjectType('Scan')
export class ScanType {
  @Field(() => ID)
  id!: string;

  @Field()
  repositoryUrl!: string;

  @Field(() => ScanStatus)
  status!: ScanStatus;

  // `criticalVulnerabilities` is intentionally absent here: it is a
  // paginated @ResolveField on ScanResolver, not a stored property. Querying
  // a scan's status therefore costs one small Redis GET and does not read the
  // findings list at all - which matters because clients poll this every 2s.

  @Field(() => Int, {
    description: 'Total number of CRITICAL findings, and the total to page through.',
  })
  criticalVulnerabilityCount!: number;

  @Field({ nullable: true })
  errorMessage?: string;

  @Field(() => GraphQLISODateTime)
  createdAt!: Date;

  @Field(() => GraphQLISODateTime)
  updatedAt!: Date;
}
