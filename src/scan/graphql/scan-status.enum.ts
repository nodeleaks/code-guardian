import { registerEnumType } from '@nestjs/graphql';
import { ScanStatus } from '../interfaces/scan-record.interface';

registerEnumType(ScanStatus, {
  name: 'ScanStatus',
  description: 'Lifecycle of a scan job.',
});

export { ScanStatus };
