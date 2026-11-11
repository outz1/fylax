import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { loadEnv } from './env';

async function bootstrap(): Promise<void> {
  loadEnv();
  const app = await NestFactory.create(AppModule);
  app.enableShutdownHooks();
  // Só localhost: a API não tem autenticação nesta fase.
  const host = process.env.API_HOST ?? '127.0.0.1';
  const port = Number(process.env.API_PORT ?? 3001);
  await app.listen(port, host);
  console.log(`api em http://${host}:${port}`);
}

void bootstrap();
