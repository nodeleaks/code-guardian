import { Field, GraphQLISODateTime, ID, Int, ObjectType } from '@nestjs/graphql';
import { ScanStatus } from './scan-status.enum';
import { VulnerabilityType } from './vulnerability.type';

@ObjectType('Scan')
export class ScanType {
  @Field(() => ID)
  id!: string;

  @Field()
  repositoryUrl!: string;

  @Field(() => ScanStatus)
  status!: ScanStatus;

  @Field(() => [VulnerabilityType])
  criticalVulnerabilities!: VulnerabilityType[];

  @Field(() => Int, {
    description: 'True number of CRITICAL findings, even if the list above was capped.',
  })
  criticalVulnerabilityCount!: number;

  @Field({
    description: 'True if criticalVulnerabilityCount exceeded the retained list size.',
  })
  criticalVulnerabilitiesTruncated!: boolean;

  @Field({ nullable: true })
  errorMessage?: string;

  @Field(() => GraphQLISODateTime)
  createdAt!: Date;

  @Field(() => GraphQLISODateTime)
  updatedAt!: Date;
}
