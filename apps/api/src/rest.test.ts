import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PrismaClient } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from './app.module';

let app: INestApplication;
const prisma = new PrismaClient();
const valor = `rest-${process.pid}-${Date.now()}.invalid`;
const nomePrograma = `programa-${process.pid}-${Date.now()}`;

beforeAll(async () => {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  app = moduleRef.createNestApplication();
  await app.init();
});

afterAll(async () => {
  const targets = await prisma.target.findMany({ where: { value: valor } });
  const ids = targets.map((t) => t.id);
  const scans = await prisma.scan.findMany({ where: { targetId: { in: ids } } });
  const scanIds = scans.map((s) => s.id);
  await prisma.finding.deleteMany({ where: { scanId: { in: scanIds } } });
  await prisma.scan.deleteMany({ where: { id: { in: scanIds } } });
  await prisma.target.deleteMany({ where: { id: { in: ids } } });
  await prisma.program.deleteMany({ where: { name: nomePrograma } });
  await prisma.$disconnect();
  await app.close();
});

describe('REST fase 0', () => {
  let scanId = '';

  it('POST /scans cria o scan (201)', async () => {
    const res = await request(app.getHttpServer())
      .post('/scans')
      .send({ targetKind: 'host', targetValue: valor, platform: 'htb', profile: 'passive' })
      .expect(201);
    expect(res.body.scanId).toMatch(/^[0-9a-f-]{36}$/);
    scanId = res.body.scanId;
  });

  it('GET /scans/:id retorna o scan criado', async () => {
    const res = await request(app.getHttpServer()).get(`/scans/${scanId}`).expect(200);
    expect(res.body.scan).toMatchObject({ id: scanId, status: 'queued', profile: 'passive' });
    expect(res.body.scan.target).toMatchObject({ kind: 'host', value: valor });
    expect(res.body).toMatchObject({ tasks: [], assetCount: 0, findingCount: 0 });
  });

  it('GET /scans lista o scan criado', async () => {
    const res = await request(app.getHttpServer()).get('/scans').expect(200);
    expect(res.body.scans.some((s: { id: string }) => s.id === scanId)).toBe(true);
  });

  it('GET /scans/:id/findings aceita filtros e retorna lista vazia', async () => {
    const res = await request(app.getHttpServer())
      .get(`/scans/${scanId}/findings?severity=high&module=web`)
      .expect(200);
    expect(res.body).toEqual({ findings: [] });
  });

  it('GET /scans/:id/findings filtra por severity e module', async () => {
    await prisma.finding.createMany({
      data: [
        {
          scanId,
          checkId: 'web.xss',
          title: 'a',
          severity: 'high',
          confidence: 'high',
          asset: 'x',
          description: 'd',
          evidence: {},
          dedupKey: 'k1',
        },
        {
          scanId,
          checkId: 'web.cors',
          title: 'b',
          severity: 'low',
          confidence: 'high',
          asset: 'x',
          description: 'd',
          evidence: {},
          dedupKey: 'k2',
        },
        {
          scanId,
          checkId: 'api.bola',
          title: 'c',
          severity: 'high',
          confidence: 'medium',
          asset: 'x',
          description: 'd',
          evidence: {},
          dedupKey: 'k3',
        },
      ],
    });
    const res = await request(app.getHttpServer())
      .get(`/scans/${scanId}/findings?severity=high&module=web`)
      .expect(200);
    expect(res.body.findings.map((f: { checkId: string }) => f.checkId)).toEqual(['web.xss']);
  });

  it('kind inválido retorna 400 de validação, não 500', async () => {
    const res = await request(app.getHttpServer())
      .post('/scans')
      .send({ targetKind: 'ftp', targetValue: valor, platform: 'htb' })
      .expect(400);
    expect(res.body.error).toBe('validation_error');
    expect(res.body.issues[0].path).toBe('targetKind');
  });

  it('bounty sem programId retorna 400', async () => {
    await request(app.getHttpServer())
      .post('/scans')
      .send({ targetKind: 'url', targetValue: `https://${valor}`, platform: 'bounty' })
      .expect(400);
  });

  it('corpo ausente retorna 400', async () => {
    await request(app.getHttpServer()).post('/scans').expect(400);
  });

  it('id malformado retorna 400 e id inexistente retorna 404', async () => {
    await request(app.getHttpServer()).get('/scans/nao-e-uuid').expect(400);
    await request(app.getHttpServer())
      .get('/scans/00000000-0000-4000-8000-000000000000')
      .expect(404);
  });

  it('filtro inválido em findings retorna 400', async () => {
    await request(app.getHttpServer()).get(`/scans/${scanId}/findings?severity=enorme`).expect(400);
  });

  it('POST/GET /programs: cria, lista e rejeita duplicado (409)', async () => {
    const programa = {
      platform: 'hackerone',
      name: nomePrograma,
      briefUrl: 'https://hackerone.com/exemplo',
      inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
      rules: {
        automation: 'allowed',
        maxRequestsPerSecond: 5,
        testAccountsOnly: true,
        forbidden: ['dos'],
      },
      reviewedAt: new Date().toISOString(),
    };
    const criado = await request(app.getHttpServer()).post('/programs').send(programa).expect(201);
    expect(criado.body.programId).toBeTruthy();

    const lista = await request(app.getHttpServer()).get('/programs').expect(200);
    expect(lista.body.programs.some((p: { name: string }) => p.name === nomePrograma)).toBe(true);

    await request(app.getHttpServer()).post('/programs').send(programa).expect(409);
    await request(app.getHttpServer()).post('/programs').send({ name: 'x' }).expect(400);
  });
});
