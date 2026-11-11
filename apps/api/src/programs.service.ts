import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type PrismaClient } from '@prisma/client';
import type { ProgramSummary } from '@fylax/core';
import { ConflictError } from './errors';
import { PrismaService } from './prisma.service';
import { createProgramSchema, parse } from './schemas';

const toJson = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

@Injectable()
export class ProgramsService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaClient) {}

  /**
   * Cadastro de programa. A validação profunda do brief e a revisão humana
   * entram na fase 6 (bounty); aqui só se valida a forma dos dados.
   */
  async createProgram(input: unknown): Promise<{ programId: string }> {
    const data = parse(createProgramSchema, input);
    try {
      const program = await this.prisma.program.create({
        data: {
          platform: data.platform,
          name: data.name,
          briefUrl: data.briefUrl,
          inScope: toJson(data.inScope),
          outOfScope: toJson(data.outOfScope),
          rules: toJson(data.rules),
          reviewedAt: data.reviewedAt,
        },
      });
      return { programId: program.id };
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        throw new ConflictError(`Já existe um programa chamado "${data.name}"`);
      }
      throw e;
    }
  }

  async listPrograms(): Promise<{ programs: ProgramSummary[] }> {
    const rows = await this.prisma.program.findMany({ orderBy: { createdAt: 'desc' } });
    return {
      programs: rows.map((p) => ({
        id: p.id,
        platform: p.platform,
        name: p.name,
        briefUrl: p.briefUrl,
        reviewedAt: p.reviewedAt.toISOString(),
      })),
    };
  }
}
