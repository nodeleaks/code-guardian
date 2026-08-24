import { Global, Module, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { AppConfig } from '../config/configuration';
import { REDIS_CLIENT } from './redis.constants';

/**
 * Dedicated ioredis connection used only for reading/writing scan records
 * (see scan/scan.repository.ts). Kept separate from the connection BullMQ
 * manages internally for the queue/worker so the two concerns (job queueing
 * vs. status/result storage) never contend over the same client instance.
 */
@Global()
@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => {
        return new Redis({
          host: config.get('redis.host', { infer: true }),
          port: config.get('redis.port', { infer: true }),
          maxRetriesPerRequest: 3,
        });
      },
    },
  ],
  exports: [REDIS_CLIENT],
})
export class RedisModule implements OnApplicationShutdown {
  async onApplicationShutdown(): Promise<void> {
    // Individual client shutdown is handled by ioredis' own process hooks;
    // nothing extra required here today. Kept as an explicit hook point so
    // future connection pooling changes have an obvious place to clean up.
  }
}
