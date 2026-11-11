import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { BullScanEnqueuer, SCAN_ENQUEUER, redisConnection } from '@fylax/queue';
import { DomainErrorFilter } from './domain-error.filter';
import { PrismaService } from './prisma.service';
import { ProgramsController } from './programs.controller';
import { ProgramsService } from './programs.service';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  controllers: [ScansController, ProgramsController],
  providers: [
    PrismaService,
    ScansService,
    ProgramsService,
    {
      provide: SCAN_ENQUEUER,
      // A conexão com o Redis só abre no primeiro enqueue (lazy).
      useFactory: () =>
        new BullScanEnqueuer(redisConnection(process.env.REDIS_URL ?? 'redis://127.0.0.1:6379')),
    },
    { provide: APP_FILTER, useClass: DomainErrorFilter },
  ],
})
export class AppModule {}
