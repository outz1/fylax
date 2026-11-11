import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaAssetSink, PrismaAuditSink, assetDedupKey } from './sinks';

const prisma = new PrismaClient();
const sufixo = `${process.pid}-${Date.now()}`;
let scanId = '';

beforeAll(async () => {
  const target = await prisma.target.create({
    data: { kind: 'host', value: `db-${sufixo}.invalid`, platform: 'local' },
  });
  scanId = (await prisma.scan.create({ data: { targetId: target.id, profile: 'passive' } })).id;
});

afterAll(async () => {
  await prisma.auditLog.deleteMany({ where: { scanId } });
  await prisma.asset.deleteMany({ where: { scanId } });
  await prisma.scan.deleteMany({ where: { id: scanId } });
  await prisma.target.deleteMany({ where: { value: { contains: sufixo } } });
  await prisma.$disconnect();
});

describe('assetDedupKey', () => {
  it('não depende da ordem das chaves e muda com o conteúdo ou o tipo', () => {
    const a = assetDedupKey({
      type: 'port',
      data: { port: 80, state: 'open', nested: { b: 1, a: 2 } },
    });
    const b = assetDedupKey({
      type: 'port',
      data: { nested: { a: 2, b: 1 }, state: 'open', port: 80 },
    });
    expect(a).toBe(b);
    expect(a).not.toBe(
      assetDedupKey({ type: 'port', data: { port: 81, state: 'open', nested: { b: 1, a: 2 } } }),
    );
    expect(a).not.toBe(
      assetDedupKey({ type: 'service', data: { port: 80, state: 'open', nested: { b: 1, a: 2 } } }),
    );
  });
});

describe('sinks no Postgres', () => {
  it('PrismaAssetSink é idempotente: o mesmo asset é gravado uma única vez', async () => {
    const sink = new PrismaAssetSink(prisma, scanId);
    await sink.record({ type: 'port', data: { port: 22, state: 'open' } });
    await sink.record({ type: 'port', data: { state: 'open', port: 22 } });
    await sink.record({ type: 'port', data: { port: 80, state: 'open' } });
    expect(await prisma.asset.count({ where: { scanId } })).toBe(2);
  });

  it('PrismaAuditSink grava a ação, o scanId e o detalhe', async () => {
    const sink = new PrismaAuditSink(prisma);
    await sink.record({ scanId, action: 'tool.exec', detail: { tool: 'x' } });
    await sink.record({ action: 'scope.block', detail: { n: randomUUID() } });
    const rows = await prisma.auditLog.findMany({ where: { scanId } });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ action: 'tool.exec', detail: { tool: 'x' } });
  });
});
