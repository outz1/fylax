import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type PrismaClient } from '@prisma/client';
import type { ScanSummary } from '@fylax/core';
import { NotFoundError } from './errors';
import { PrismaService } from './prisma.service';
import {
  createScanSchema,
  findingsQuerySchema,
  idSchema,
  parse,
  type CreateScanInput,
} from './schemas';

const LIMITE_LISTAGEM = 200;

@Injectable()
export class ScansService {
  // @Inject explícito: o esbuild (tsx/vitest) não emite metadata de decorators.
  constructor(@Inject(PrismaService) private readonly prisma: PrismaClient) {}

  /**
   * Caso de uso createScan. Fase 0: só persiste o scan com status `queued`;
   * nenhum worker consome e nenhum tráfego é gerado.
   */
  async createScan(input: CreateScanInput | unknown): Promise<{ scanId: string }> {
    const data = parse(createScanSchema, input);

    if (data.programId) {
      const program = await this.prisma.program.findUnique({ where: { id: data.programId } });
      if (!program) throw new NotFoundError(`Program ${data.programId} não encontrado`);
    }

    const scan = await this.prisma.$transaction(async (tx) => {
      const target = await tx.target.upsert({
        where: {
          kind_value_platform: {
            kind: data.targetKind,
            value: data.targetValue,
            platform: data.platform,
          },
        },
        create: {
          kind: data.targetKind,
          value: data.targetValue,
          platform: data.platform,
          programId: data.programId ?? null,
        },
        update: data.programId ? { programId: data.programId } : {},
      });
      return tx.scan.create({
        data: { targetId: target.id, profile: data.profile, status: 'queued' },
      });
    });

    return { scanId: scan.id };
  }

  async listScans(): Promise<{ scans: ScanSummary[] }> {
    const rows = await this.prisma.scan.findMany({
      orderBy: { createdAt: 'desc' },
      take: LIMITE_LISTAGEM,
      include: { target: true },
    });
    return {
      scans: rows.map((s) => ({
        id: s.id,
        targetId: s.targetId,
        targetKind: s.target.kind,
        targetValue: s.target.value,
        platform: s.target.platform,
        profile: s.profile,
        status: s.status,
        createdAt: s.createdAt.toISOString(),
      })),
    };
  }

  async getScan(rawId: string) {
    const id = parse(idSchema, rawId);
    const scan = await this.prisma.scan.findUnique({
      where: { id },
      include: { target: true, tasks: { orderBy: { createdAt: 'asc' } } },
    });
    if (!scan) throw new NotFoundError(`Scan ${id} não encontrado`);

    const [assetCount, findingCount] = await Promise.all([
      this.prisma.asset.count({ where: { scanId: id } }),
      this.prisma.finding.count({ where: { scanId: id } }),
    ]);
    const { tasks, ...scanRow } = scan;
    return { scan: scanRow, tasks, assetCount, findingCount };
  }

  async listFindings(rawId: string, rawQuery: unknown) {
    const id = parse(idSchema, rawId);
    const query = parse(findingsQuerySchema, rawQuery);
    const exists = await this.prisma.scan.count({ where: { id } });
    if (exists === 0) throw new NotFoundError(`Scan ${id} não encontrado`);

    const where: Prisma.FindingWhereInput = { scanId: id };
    if (query.severity) where.severity = query.severity;
    // Convenção: checkId = "<module>.<nome>" (ver biblioteca/pesquisa/FASE-0.md, D2).
    if (query.module) where.checkId = { startsWith: `${query.module}.` };

    const findings = await this.prisma.finding.findMany({
      where,
      orderBy: { createdAt: 'asc' },
    });
    return { findings };
  }
}
