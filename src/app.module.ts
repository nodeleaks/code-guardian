import { BullModule } from '@nestjs/bullmq';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { ThrottlerModule } from '@nestjs/throttler';
import { join } from 'node:path';
import * as Joi from 'joi';
import configuration, { AppConfig } from './config/configuration';
import { GqlThrottlerGuard } from './common/guards/gql-throttler.guard';
import { RedisModule } from './redis/redis.module';
import { ScanModule } from './scan/scan.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      // Fail at boot on a malformed value rather than silently producing
      // NaN - `PORT=abc` would otherwise reach app.listen(NaN) and bind a
      // random port, and a bad TTL would reach `SET ... EX NaN` and make
      // every scan fail at runtime with no startup signal.
      validationSchema: Joi.object({
        PORT: Joi.number().port().default(3000),
        REDIS_HOST: Joi.string().default('localhost'),
        REDIS_PORT: Joi.number().port().default(6379),
        REDIS_PASSWORD: Joi.string().allow('').optional(),
        REDIS_TLS: Joi.string().valid('true', 'false').default('false'),
        TRIVY_BINARY_PATH: Joi.string().default('trivy'),
        SCAN_RECORD_TTL_SECONDS: Joi.number().positive().default(86400),
        SCAN_TIMEOUT_MS: Joi.number().positive().default(300000),
        SCAN_MAX_REPO_SIZE_MB: Joi.number().positive().default(1024),
        SCAN_MAX_QUEUE_DEPTH: Joi.number().positive().default(100),
        CORS_ORIGIN: Joi.string().allow('').optional(),
        GRAPHQL_PLAYGROUND: Joi.string().valid('true', 'false').default('false'),
      }),
      validationOptions: { allowUnknown: true, abortEarly: false },
    }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => {
        const playground = config.get('graphql.playground', { infer: true });
        return {
          autoSchemaFile:
            process.env.NODE_ENV === 'production' ? true : join(process.cwd(), 'schema.gql'),
          sortSchema: true,
          // Both gated on the same explicit flag. Relying on NODE_ENV alone
          // left introspection on for `npm run start:prod`, which never sets it.
          playground,
          introspection: playground,
          // GqlThrottlerGuard reads req/res off the Apollo context to
          // identify the caller and write rate-limit headers. Without this
          // they are undefined and every guarded resolver 500s.
          context: ({ req, res }: { req: unknown; res: unknown }) => ({ req, res }),
        };
      },
    }),
    // Bounds how fast a single client can enqueue scans. Each scan is an
    // outbound git clone plus a trivy run, so an unthrottled mutation is a
    // one-line resource-exhaustion vector against a 200m container.
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 30 }]),
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => {
        const host: string = config.get('redis.host', { infer: true });
        const port: number = config.get('redis.port', { infer: true });
        const password = config.get('redis.password', { infer: true });
        const tls = config.get('redis.tls', { infer: true });
        return {
          connection: {
            host,
            port,
            ...(password ? { password } : {}),
            ...(tls ? { tls: {} } : {}),
          },
        };
      },
    }),
    RedisModule,
    ScanModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: GqlThrottlerGuard }],
})
export class AppModule {}
