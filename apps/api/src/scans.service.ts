import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type PrismaClient } from '@prisma/client';
import type { ScanQueueName, ScanSummary } from '@fylax/core';
import { SCAN_ENQUEUER, type ScanEnqueuer } from '@fylax/queue';
import { ScopeContextError, needsConfirmation, resolveScanContext } from '@fylax/scope';
import { ConflictError, NotFoundError } from './errors';
import { PrismaService } from './prisma.service';
import {
  createScanSchema,
  findingsQuerySchema,
  idSchema,
  parse,
  type CreateScanInput,
} from './schemas';
import { PrismaAuditSink } from '@fylax/db';

const LIMITE_LISTAGEM = 200;

export type RunResult =
  | { scanId: string; state: 'enqueued'; queue: ScanQueueName }
  | { scanId: string; state: 'awaiting_confirmation' };

@Injectable()
export class ScansService {
  private readonly audit: PrismaAuditSink;

  // @Inject explícito: o esbuild (tsx/vitest) não emite metadata de decorators.
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaClient,
    @Inject(SCAN_ENQUEUER) private readonly enqueuer: ScanEnqueuer,
  ) {
    this.audit = new PrismaAuditSink(prisma);
  }

  /**
   * Caso de uso createScan: persiste o scan com status `queued`.
   * Não gera tráfego; a execução começa só com `runScan`.
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

  private async loadScan(rawId: string) {
    const id = parse(idSchema, rawId);
    const scan = await this.prisma.scan.findUnique({
      where: { id },
      include: { target: { include: { program: true } } },
    });
    if (!scan) throw new NotFoundError(`Scan ${id} não encontrado`);
    return scan;
  }

  /**
   * Exige confirmação só quando o escopo do programa pede (automation unspecified).
   * Scans de lab não dependem do programa e nunca exigem.
   */
  private requiresConfirmation(scan: Awaited<ReturnType<ScansService['loadScan']>>): boolean {
    if (scan.target.platform !== 'bounty') return false;
    try {
      const ctx = resolveScanContext(
        { platform: scan.target.platform, program: scan.target.program },
        {},
        () => undefined,
      );
      return needsConfirmation(ctx);
    } catch (e) {
      if (e instanceof ScopeContextError) throw new ConflictError(e.message);
      throw e;
    }
  }

  /**
   * Enfileira o scan. Se o escopo exige confirmação humana e ela não existe,
   * o scan fica em `queued`, fora da fila, até `confirmScan`.
   */
  async runScan(rawId: string): Promise<RunResult> {
    const scan = await this.loadScan(rawId);
    if (scan.status !== 'queued') {
      throw new ConflictError(
        `Scan ${scan.id} está "${scan.status}"; só scans "queued" podem rodar`,
      );
    }
    if (this.requiresConfirmation(scan) && !scan.confirmedAt) {
      return { scanId: scan.id, state: 'awaiting_confirmation' };
    }
    const queue = await this.enqueuer.enqueue(scan.id, scan.target.platform);
    return { scanId: scan.id, state: 'enqueued', queue };
  }

  /** Confirmação humana: grava `confirmedAt`, audita e enfileira. Idempotente. */
  async confirmScan(rawId: string) {
    const scan = await this.loadScan(rawId);
    if (scan.status !== 'queued') {
      throw new ConflictError(
        `Scan ${scan.id} está "${scan.status}"; só scans "queued" aceitam confirmação`,
      );
    }
    if (!this.requiresConfirmation(scan)) {
      throw new ConflictError(`Scan ${scan.id} não exige confirmação`);
    }

    let confirmedAt = scan.confirmedAt;
    if (!confirmedAt) {
      confirmedAt = new Date();
      await this.prisma.scan.update({ where: { id: scan.id }, data: { confirmedAt } });
      await this.audit.record({
        scanId: scan.id,
        action: 'scan.confirm',
        detail: { program: scan.target.program?.name ?? null, target: scan.target.value },
      });
    }
    const queue = await this.enqueuer.enqueue(scan.id, scan.target.platform);
    return { scanId: scan.id, confirmedAt: confirmedAt.toISOString(), queue };
  }

  /** Cancela um scan `queued` ou `running`. O worker para entre passos e encerra o que estiver em curso. */
  async cancelScan(rawId: string) {
    const scan = await this.loadScan(rawId);
    const result = await this.prisma.scan.updateMany({
      where: { id: scan.id, status: { in: ['queued', 'running'] } },
      data: { status: 'canceled', finishedAt: new Date() },
    });
    if (result.count === 0) {
      throw new ConflictError(
        `Scan ${scan.id} está "${scan.status}"; só "queued" ou "running" podem ser cancelados`,
      );
    }
    await this.audit.record({
      scanId: scan.id,
      action: 'scan.cancel',
      detail: { previousStatus: scan.status, target: scan.target.value },
    });
    // Se o job ainda não começou, tira da fila. Se falhar, o worker vê "canceled" e ignora.
    await this.enqueuer.remove(scan.id, scan.target.platform).catch(() => undefined);
    return { scanId: scan.id, status: 'canceled' as const };
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
