import { Body, Controller, Get, HttpCode, Inject, Post } from '@nestjs/common';
import { ProgramsService } from './programs.service';

@Controller('programs')
export class ProgramsController {
  constructor(@Inject(ProgramsService) private readonly programs: ProgramsService) {}

  @Post()
  @HttpCode(201)
  create(@Body() body: unknown) {
    return this.programs.createProgram(body);
  }

  @Get()
  list() {
    return this.programs.listPrograms();
  }
}
