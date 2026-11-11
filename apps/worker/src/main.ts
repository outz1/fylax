import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { loadEnv } from '@fylax/db';
import { WorkerService } from './worker.service';

@Module({ providers: [WorkerService] })
class WorkerModule {}

async function bootstrap(): Promise<void> {
  loadEnv();
  const app = await NestFactory.createApplicationContext(WorkerModule);
  app.enableShutdownHooks();
}

void bootstrap();
