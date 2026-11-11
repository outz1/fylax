import { PrismaClient } from '@prisma/client';
import { afterAll, describe, expect, it } from 'vitest';
import type { ScanQueueName, TargetPlatform } from '@fylax/core';
import { ORPHAN_ERROR, reapOrphanedScans, type JobState } from './reaper';

const prisma = new PrismaClient();
const sufixo = `${process.pid}-${Date.now()}`;
const AGORA = new Date('2026-11-11T12:00:00Z');
const minutosAtras = (m: number) => new Date(AGORA.getTime() - m * 60_000);
let contador = 0;

async function scan(over: {
  status?: 'queued' | 'running' | 'done' | 'canceled';
  startedAt?: Date | null;
  platform?: TargetPlatform;
}) {
  const target = await prisma.target.create({
    data: {
      kind: 'host',
      value: `reaper-${contador++}-${sufixo}.invalid`,
      platform: over.platform ?? 'htb',
    },
  });
  const s = await prisma.scan.create({
    data: {
      targetId: target.id,
      profile: 'standard',
      status: over.status ?? 'running',
      startedAt: over.startedAt === undefined ? minutosAtras(30) : over.startedAt,
    },
  });
  return s.id;
}

function reap(
  estados: Record<string, JobState>,
  queue: ScanQueueName = 'scans-lab',
  graceMs?: number,
) {
  return reapOrphanedScans({
    prisma,
    queue,
    now: () => AGORA,
    ...(graceMs !== undefined ? { graceMs } : {}),
    jobState: async (id) => estados[id] ?? 'missing',
  });
}

const status = async (id: string) => prisma.scan.findUniqueOrThrow({ where: { id } });

afterAll(async () => {
  const targets = await prisma.target.findMany({ where: { value: { contains: sufixo } } });
  const ids = (
    await prisma.scan.findMany({ where: { targetId: { in: targets.map((t) => t.id) } } })
  ).map((s) => s.id);
  await prisma.task.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.scan.deleteMany({ where: { id: { in: ids } } });
  await prisma.target.deleteMany({ where: { id: { in: targets.map((t) => t.id) } } });
  await prisma.$disconnect();
});

describe('reapOrphanedScans', () => {
  it('encerra o scan running cujo job sumiu ou já terminou, e marca as tasks em andamento', async () => {
    const sumiu = await scan({});
    const terminou = await scan({});
    const falhou = await scan({});
    await prisma.task.create({
      data: { scanId: sumiu, module: 'recon', status: 'running', attempts: 1 },
    });
    await prisma.task.create({
      data: { scanId: sumiu, module: 'web', status: 'pending', attempts: 1 },
    });
    await prisma.task.create({
      data: { scanId: sumiu, module: 'api', status: 'done', attempts: 1 },
    });

    const reaped = await reap({ [terminou]: 'completed', [falhou]: 'failed' }); // `sumiu` não tem job
    expect(reaped.sort()).toEqual([sumiu, terminou, falhou].sort());

    for (const id of [sumiu, terminou, falhou]) {
      const s = await status(id);
      expect(s.status).toBe('failed');
      expect(s.error).toBe(ORPHAN_ERROR);
      expect(s.finishedAt?.toISOString()).toBe(AGORA.toISOString());
    }
    const tasks = await prisma.task.findMany({
      where: { scanId: sumiu },
      orderBy: { module: 'asc' },
    });
    expect(tasks.map((t) => [t.module, t.status])).toEqual([
      ['api', 'done'], // o que já terminou fica
      ['recon', 'failed'],
      ['web', 'failed'],
    ]);
  });

  it('não toca em scan com job vivo: ativo, esperando, agendado ou priorizado', async () => {
    const ids = {
      active: await scan({}),
      waiting: await scan({}),
      delayed: await scan({}),
      prioritized: await scan({}),
    };
    const reaped = await reap({
      [ids.active]: 'active',
      [ids.waiting]: 'waiting',
      [ids.delayed]: 'delayed',
      [ids.prioritized]: 'prioritized',
    });
    expect(reaped).toEqual([]);
    for (const id of Object.values(ids)) expect((await status(id)).status).toBe('running');
    await prisma.scan.updateMany({
      where: { id: { in: Object.values(ids) } },
      data: { status: 'done' },
    });
  });

  it('respeita o período de graça: scan recém-iniciado não é tocado', async () => {
    const recente = await scan({ startedAt: minutosAtras(1) });
    expect(await reap({}, 'scans-lab', 120_000)).not.toContain(recente);
    expect((await status(recente)).status).toBe('running');
    // com graça menor que a idade, passa a valer
    expect(await reap({}, 'scans-lab', 30_000)).toContain(recente);
    expect((await status(recente)).status).toBe('failed');
  });

  it('só considera scans das plataformas da fila do worker', async () => {
    const local = await scan({ platform: 'local' });
    const htb = await scan({ platform: 'htb' });

    const doLab = await reap({}, 'scans-lab');
    expect(doLab).toContain(htb);
    expect(doLab).not.toContain(local);
    expect((await status(local)).status).toBe('running');

    expect(await reap({}, 'scans-local')).toContain(local);
    expect((await status(local)).status).toBe('failed');
  });

  it('não mexe em scans queued, done, canceled nem sem startedAt', async () => {
    const queued = await scan({ status: 'queued', startedAt: null });
    const done = await scan({ status: 'done' });
    const canceled = await scan({ status: 'canceled' });
    const semInicio = await scan({ status: 'running', startedAt: null });

    const reaped = await reap({});
    for (const id of [queued, done, canceled, semInicio]) expect(reaped).not.toContain(id);
    expect((await status(queued)).status).toBe('queued');
    expect((await status(done)).status).toBe('done');
    expect((await status(canceled)).status).toBe('canceled');
    expect((await status(semInicio)).status).toBe('running');
    await prisma.scan.update({ where: { id: semInicio }, data: { status: 'done' } });
  });

  it('é idempotente e não sobrescreve scan que terminou no meio do caminho', async () => {
    const id = await scan({});
    expect(await reap({})).toContain(id);
    expect(await reap({})).not.toContain(id); // segunda passada: nada a fazer

    // O estado do job é consultado ANTES do update condicional: se o scan terminar nesse intervalo, vale o novo estado.
    const corrida = await scan({});
    const reaped = await reapOrphanedScans({
      prisma,
      queue: 'scans-lab',
      now: () => AGORA,
      jobState: async (sid) => {
        if (sid === corrida)
          await prisma.scan.update({ where: { id: sid }, data: { status: 'done' } });
        return 'missing';
      },
    });
    expect(reaped).not.toContain(corrida);
    expect((await status(corrida)).status).toBe('done');
  });
});
