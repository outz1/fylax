import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaClient } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SCAN_ENQUEUER } from '@fylax/queue';
import { AppModule } from './app.module';
import { ConflictError, NotFoundError } from './errors';
import { ProgramsService } from './programs.service';
import { ScansService } from './scans.service';
import { FakeEnqueuer } from './testing';

const prisma = new PrismaClient();
const enqueuer = new FakeEnqueuer();
const service = new ScansService(prisma, enqueuer);
const programs = new ProgramsService(prisma);
const sufixo = `${process.pid}-${Date.now()}`;
const scanIds: string[] = [];

let contador = 0;

async function programa(automation: 'allowed' | 'unspecified' | 'forbidden') {
  const name = `lifecycle-${automation}-${contador++}-${sufixo}`;
  const { programId } = await programs.createProgram({
    platform: 'hackerone',
    name,
    briefUrl: 'https://hackerone.com/exemplo',
    inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
    rules: { automation, maxRequestsPerSecond: 5, testAccountsOnly: false, forbidden: [] },
    reviewedAt: new Date().toISOString(),
  });
  return programId;
}

async function novoScan(over: Record<string, unknown> = {}): Promise<string> {
  const { scanId } = await service.createScan({
    targetKind: 'host',
    targetValue: `lc-${scanIds.length}-${sufixo}.invalid`,
    platform: 'htb',
    ...over,
  });
  scanIds.push(scanId);
  return scanId;
}

let app: INestApplication;

beforeAll(async () => {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(SCAN_ENQUEUER)
    .useValue(enqueuer)
    .compile();
  app = moduleRef.createNestApplication();
  await app.init();
});

afterAll(async () => {
  await prisma.auditLog.deleteMany({ where: { scanId: { in: scanIds } } });
  await prisma.scan.deleteMany({ where: { id: { in: scanIds } } });
  await prisma.target.deleteMany({ where: { value: { contains: sufixo } } });
  await prisma.program.deleteMany({ where: { name: { contains: sufixo } } });
  await prisma.$disconnect();
  await app.close();
});

describe('run', () => {
  it('scan de lab entra na fila scans-lab', async () => {
    const id = await novoScan();
    expect(await service.runScan(id)).toEqual({
      scanId: id,
      state: 'enqueued',
      queue: 'scans-lab',
    });
    expect(enqueuer.enqueued.at(-1)).toEqual({ scanId: id, queue: 'scans-lab' });
  });

  it('só scans queued podem rodar', async () => {
    const id = await novoScan();
    await prisma.scan.update({ where: { id }, data: { status: 'done' } });
    await expect(service.runScan(id)).rejects.toBeInstanceOf(ConflictError);
  });

  it('scan inexistente retorna not found', async () => {
    await expect(service.runScan('00000000-0000-4000-8000-000000000000')).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it('programa com automation allowed entra direto na fila scans-bounty', async () => {
    const programId = await programa('allowed');
    const id = await novoScan({
      targetKind: 'url',
      targetValue: `https://a-${sufixo}.exemplo.com`,
      platform: 'bounty',
      programId,
    });
    expect(await service.runScan(id)).toEqual({
      scanId: id,
      state: 'enqueued',
      queue: 'scans-bounty',
    });
  });
});

describe('confirmação humana (automation unspecified)', () => {
  it('run não enfileira sem confirmação; confirm grava confirmedAt, audita e enfileira', async () => {
    const programId = await programa('unspecified');
    const id = await novoScan({
      targetKind: 'url',
      targetValue: `https://u-${sufixo}.exemplo.com`,
      platform: 'bounty',
      programId,
    });
    const antes = enqueuer.enqueued.length;

    expect(await service.runScan(id)).toEqual({ scanId: id, state: 'awaiting_confirmation' });
    expect(enqueuer.enqueued.length).toBe(antes);
    expect((await prisma.scan.findUniqueOrThrow({ where: { id } })).status).toBe('queued');

    const confirmado = await service.confirmScan(id);
    expect(confirmado).toMatchObject({ scanId: id, queue: 'scans-bounty' });
    expect(enqueuer.enqueued.length).toBe(antes + 1);
    const row = await prisma.scan.findUniqueOrThrow({ where: { id } });
    expect(row.confirmedAt?.toISOString()).toBe(confirmado.confirmedAt);

    const audit = await prisma.auditLog.findMany({ where: { scanId: id, action: 'scan.confirm' } });
    expect(audit).toHaveLength(1);
    expect(audit[0]?.detail).toMatchObject({ target: `https://u-${sufixo}.exemplo.com` });

    // Idempotente: não regrava a confirmação nem duplica o audit.
    const de_novo = await service.confirmScan(id);
    expect(de_novo.confirmedAt).toBe(confirmado.confirmedAt);
    expect(await prisma.auditLog.count({ where: { scanId: id, action: 'scan.confirm' } })).toBe(1);

    // Depois de confirmado, run enfileira.
    expect((await service.runScan(id)).state).toBe('enqueued');
  });

  it('confirm em scan que não exige confirmação é conflito', async () => {
    const lab = await novoScan();
    await expect(service.confirmScan(lab)).rejects.toBeInstanceOf(ConflictError);

    const programId = await programa('allowed');
    const bounty = await novoScan({
      targetKind: 'url',
      targetValue: `https://c-${sufixo}.exemplo.com`,
      platform: 'bounty',
      programId,
    });
    await expect(service.confirmScan(bounty)).rejects.toBeInstanceOf(ConflictError);
  });
});

describe('cancel', () => {
  it('cancela queued, audita e tira da fila; segundo cancel é conflito', async () => {
    const id = await novoScan();
    await service.runScan(id);
    expect(await service.cancelScan(id)).toEqual({ scanId: id, status: 'canceled' });

    const row = await prisma.scan.findUniqueOrThrow({ where: { id } });
    expect(row.status).toBe('canceled');
    expect(row.finishedAt).not.toBeNull();
    expect(enqueuer.removed).toContain(id);
    const audit = await prisma.auditLog.findMany({ where: { scanId: id, action: 'scan.cancel' } });
    expect(audit[0]?.detail).toMatchObject({ previousStatus: 'queued' });

    await expect(service.cancelScan(id)).rejects.toBeInstanceOf(ConflictError);
    await expect(service.runScan(id)).rejects.toBeInstanceOf(ConflictError);
  });

  it('cancela um scan running', async () => {
    const id = await novoScan();
    await prisma.scan.update({ where: { id }, data: { status: 'running', startedAt: new Date() } });
    await service.cancelScan(id);
    expect((await prisma.scan.findUniqueOrThrow({ where: { id } })).status).toBe('canceled');
  });

  it('não cancela scan já finalizado', async () => {
    const id = await novoScan();
    await prisma.scan.update({ where: { id }, data: { status: 'done' } });
    await expect(service.cancelScan(id)).rejects.toBeInstanceOf(ConflictError);
    expect((await prisma.scan.findUniqueOrThrow({ where: { id } })).status).toBe('done');
  });
});

describe('REST', () => {
  it('POST run 202, confirm 200 e cancel 200, com 409 e 404 nos casos de erro', async () => {
    const http = request(app.getHttpServer());
    const lab = await novoScan();

    const run = await http.post(`/scans/${lab}/run`).expect(202);
    expect(run.body).toEqual({ scanId: lab, state: 'enqueued', queue: 'scans-lab' });

    const conflito = await http.post(`/scans/${lab}/confirm`).expect(409);
    expect(conflito.body.error).toBe('conflict');

    await http.post(`/scans/${lab}/cancel`).expect(200);
    await http.post(`/scans/${lab}/cancel`).expect(409);
    await http.post('/scans/00000000-0000-4000-8000-000000000000/run').expect(404);
    await http.post('/scans/nao-e-uuid/run').expect(400);
  });

  it('GET /scans/:id expõe confirmedAt e error', async () => {
    const id = await novoScan();
    const res = await request(app.getHttpServer()).get(`/scans/${id}`).expect(200);
    expect(res.body.scan).toMatchObject({ confirmedAt: null, error: null, status: 'queued' });
  });
});
