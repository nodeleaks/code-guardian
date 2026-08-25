import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AppConfig } from './config/configuration';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = app.get(ConfigService<AppConfig, true>);
  const port = config.get('port', { infer: true });

  app.enableCors({ origin: config.get('cors.origin', { infer: true }) });

  // Required for RedisModule.onApplicationShutdown to ever run - without it
  // Nest skips lifecycle shutdown hooks entirely and the Redis connection is
  // dropped on SIGTERM rather than closed cleanly.
  app.enableShutdownHooks();

  await app.listen(port);
  console.log(`Code Guardian listening on http://localhost:${port}/graphql`);
}

void bootstrap();
