import { createHash } from 'node:crypto';
import type { Asset, AssetSink, AuditEntry, AuditSink } from '@fylax/core';
import { Prisma, type PrismaClient } from '@prisma/client';

const toJson = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

/** JSON com chaves ordenadas: o mesmo conteúdo gera sempre a mesma string. */
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function assetDedupKey(asset: Asset): string {
  return createHash('sha256')
    .update(`${asset.type}\n${stableJson(asset.data)}`)
    .digest('hex');
}

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

/** Assets de um scan. Idempotente: o mesmo asset (tipo + dados) é gravado uma única vez. */
export class PrismaAssetSink implements AssetSink {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly scanId: string,
  ) {}

  async record(asset: Asset): Promise<void> {
    await this.prisma.asset.createMany({
      data: [
        {
          scanId: this.scanId,
          type: asset.type,
          data: toJson(asset.data),
          dedupKey: assetDedupKey(asset),
        },
      ],
      skipDuplicates: true,
    });
  }
}
