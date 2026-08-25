import { Global, Inject, Logger, Module, OnApplicationShutdown } from '@nestjs/common';
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
        const logger = new Logger('RedisClient');
        const tls = config.get('redis.tls', { infer: true });
        const password = config.get('redis.password', { infer: true });

        const client = new Redis({
          host: config.get('redis.host', { infer: true }),
          port: config.get('redis.port', { infer: true }),
          maxRetriesPerRequest: 3,
          ...(password ? { password } : {}),
          ...(tls ? { tls: {} } : {}),
        });

        // Not optional: ioredis' client is an EventEmitter, and Node throws
        // on an 'error' event with no listener registered - which would take
        // the whole process down on any transient Redis blip (restart,
        // network partition, failed AUTH). Registering a listener downgrades
        // that to a logged error while ioredis retries in the background.
        client.on('error', (err: Error) => {
          logger.error(`Redis connection error: ${err.message}`);
        });

        return client;
      },
    },
  ],
  exports: [REDIS_CLIENT],
})
export class RedisModule implements OnApplicationShutdown {
  private readonly logger = new Logger(RedisModule.name);

  constructor(@Inject(REDIS_CLIENT) private readonly redis: Redis) {}

  async onApplicationShutdown(): Promise<void> {
    // Requires app.enableShutdownHooks() in main.ts - without it Nest never
    // calls this and the connection is dropped rather than closed.
    try {
      await this.redis.quit();
    } catch (err) {
      // Already disconnected, or the server went away first - nothing left
      // to close, and throwing here would mask the real shutdown reason.
      this.logger.warn(
        `Ignoring error while closing Redis connection: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}
