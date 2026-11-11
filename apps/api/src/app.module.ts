import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
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
    { provide: APP_FILTER, useClass: DomainErrorFilter },
  ],
})
export class AppModule {}
