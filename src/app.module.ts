import { BullModule } from '@nestjs/bullmq';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { join } from 'node:path';
import configuration, { AppConfig } from './config/configuration';
import { RedisModule } from './redis/redis.module';
import { ScanModule } from './scan/scan.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [configuration] }),
    GraphQLModule.forRootAsync<ApolloDriverConfig>({
      driver: ApolloDriver,
      useFactory: () => ({
        autoSchemaFile:
          process.env.NODE_ENV === 'production' ? true : join(process.cwd(), 'schema.gql'),
        sortSchema: true,
        playground: true,
      }),
    }),
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) => {
        const host: string = config.get('redis.host', { infer: true });
        const port: number = config.get('redis.port', { infer: true });
        return { connection: { host, port } };
      },
    }),
    RedisModule,
    ScanModule,
  ],
})
export class AppModule {}
