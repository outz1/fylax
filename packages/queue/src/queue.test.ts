import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { SCAN_QUEUES } from '@fylax/core';
import { BullScanEnqueuer, Queue, redisConnection } from './index';

describe('redisConnection', () => {
  it('converte a URL em opções de conexão', () => {
    expect(redisConnection('redis://127.0.0.1:6379')).toEqual({ host: '127.0.0.1', port: 6379 });
    expect(redisConnection('redis://u:p%40ss@redis:6380/2')).toEqual({
      host: 'redis',
      port: 6380,
      username: 'u',
      password: 'p@ss',
      db: 2,
    });
    expect(redisConnection('rediss://h')).toMatchObject({ host: 'h', port: 6379, tls: {} });
  });

  it('recusa esquema que não é redis', () => {
    expect(() => redisConnection('http://x')).toThrow(/REDIS_URL inválida/);
  });
});

describe('BullScanEnqueuer (Redis real)', () => {
  const url = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';
  const enqueuer = new BullScanEnqueuer(redisConnection(url));
  const ids: string[] = [];

  afterAll(async () => {
    const lab = new Queue(SCAN_QUEUES.lab, { connection: redisConnection(url) });
    const bounty = new Queue(SCAN_QUEUES.bounty, { connection: redisConnection(url) });
    for (const id of ids) {
      await (await lab.getJob(id))?.remove().catch(() => undefined);
      await (await bounty.getJob(id))?.remove().catch(() => undefined);
    }
    await Promise.all([lab.close(), bounty.close(), enqueuer.close()]);
  });

  it('roteia por plataforma e é idempotente pelo scanId', async () => {
    const lab = randomUUID();
    const bounty = randomUUID();
    ids.push(lab, bounty);

    expect(await enqueuer.enqueue(lab, 'htb')).toBe('scans-lab');
    expect(await enqueuer.enqueue(lab, 'htb')).toBe('scans-lab');
    expect(await enqueuer.enqueue(bounty, 'bounty')).toBe('scans-bounty');

    const q = new Queue(SCAN_QUEUES.lab, { connection: redisConnection(url) });
    const jobs = (await q.getWaiting()).filter((j) => j.id === lab);
    await q.close();
    expect(jobs).toHaveLength(1);
    expect(jobs[0]?.data).toEqual({ scanId: lab });
  });

  it('remove um job que ainda está na fila', async () => {
    const id = randomUUID();
    ids.push(id);
    await enqueuer.enqueue(id, 'thm');
    await enqueuer.remove(id, 'thm');
    const q = new Queue(SCAN_QUEUES.lab, { connection: redisConnection(url) });
    expect(await q.getJob(id)).toBeUndefined();
    await q.close();
  });
});
