import { Body, Controller, Get, HttpCode, Inject, Param, Post, Query } from '@nestjs/common';
import { ScansService } from './scans.service';

@Controller('scans')
export class ScansController {
  constructor(@Inject(ScansService) private readonly scans: ScansService) {}

  @Post()
  @HttpCode(201)
  create(@Body() body: unknown) {
    return this.scans.createScan(body);
  }

  @Get()
  list() {
    return this.scans.listScans();
  }

  @Get(':id')
  get(@Param('id') id: string) {
    return this.scans.getScan(id);
  }

  @Get(':id/findings')
  findings(@Param('id') id: string, @Query() query: unknown) {
    return this.scans.listFindings(id, query);
  }
}
