import type { Asset, AssetSink, AuditEntry, AuditSink } from '@fylax/core';
import { Prisma, type PrismaClient } from '@prisma/client';

const toJson = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

/** AuditLog no Postgres. Se a gravação falhar, o erro sobe e o chamador não envia tráfego. */
export class PrismaAuditSink implements AuditSink {
  constructor(private readonly prisma: PrismaClient) {}

  async record(entry: AuditEntry): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        scanId: entry.scanId ?? null,
        action: entry.action,
        detail: toJson(entry.detail),
      },
    });
  }
}

/** Assets descobertos por um scan (ex.: destino de redirect não seguido). */
export class PrismaAssetSink implements AssetSink {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly scanId: string,
  ) {}

  async record(asset: Asset): Promise<void> {
    await this.prisma.asset.create({
      data: { scanId: this.scanId, type: asset.type, data: toJson(asset.data) },
    });
  }
}
