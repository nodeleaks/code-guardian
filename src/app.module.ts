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
        // Code-first: schema is generated from the @ObjectType/@InputType
        // classes under src/scan/graphql and src/scan/dto, then written out
        // so it can be committed/reviewed like any other generated artifact.
        autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
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
