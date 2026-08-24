import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { SCAN_QUEUE_NAME } from './interfaces/scan-record.interface';
import { ScanProcessor } from './scan.processor';
import { ScanRepository } from './scan.repository';
import { ScanResolver } from './scan.resolver';
import { ScanService } from './scan.service';
import { GitClonerService } from './trivy/git-cloner.service';
import { TrivyRunnerService } from './trivy/trivy-runner.service';
import { TrivyStreamParserService } from './trivy/trivy-stream-parser.service';

@Module({
  imports: [BullModule.registerQueue({ name: SCAN_QUEUE_NAME })],
  providers: [
    ScanResolver,
    ScanService,
    ScanRepository,
    ScanProcessor,
    GitClonerService,
    TrivyRunnerService,
    TrivyStreamParserService,
  ],
})
export class ScanModule {}
