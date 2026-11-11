import type { PrismaClient } from '@prisma/client';
import { TARGET_PLATFORMS, queueForPlatform, type ScanQueueName } from '@fylax/core';

/** Estado de um job na fila, ou 'missing' se ele não existe mais (Redis limpo, job expirado). */
export type JobState =
  | 'active'
  | 'waiting'
  | 'delayed'
  | 'prioritized'
  | 'waiting-children'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'missing';

/** Estados em que o job ainda vai ser executado ou retomado: o scan NÃO é órfão. */
const VIVO: ReadonlySet<JobState> = new Set([
  'active',
  'waiting',
  'delayed',
  'prioritized',
  'waiting-children',
]);

export interface ReaperDeps {
  prisma: PrismaClient;
  /** Fila deste worker: só scans das plataformas dela são considerados. */
  queue: ScanQueueName;
  jobState: (scanId: string) => Promise<JobState>;
  /** Scans iniciados há menos que isso são ignorados (evita corrida com o próprio início). */
  graceMs?: number;
  now?: () => Date;
}

export const ORPHAN_ERROR =
  'execução interrompida: o job deste scan não está mais ativo na fila (worker reiniciado ou perdido). Crie um novo scan.';

/**
 * Encerra scans que ficaram `running` sem ninguém executando.
 *
 * O BullMQ reentrega sozinho um job cujo worker morreu (e o processador retoma o scan). O que sobra
 * são scans `running` cujo job já terminou ou sumiu da fila: nada vai executá-los, e sem isto eles
 * ficariam `running` até alguém cancelar. Scans com job vivo (ativo, esperando ou agendado) nunca
 * são tocados. Devolve os ids encerrados.
 */
export async function reapOrphanedScans(d: ReaperDeps): Promise<string[]> {
  const now = d.now?.() ?? new Date();
  const cutoff = new Date(now.getTime() - (d.graceMs ?? 120_000));
  const platforms = TARGET_PLATFORMS.filter((p) => queueForPlatform(p) === d.queue);

  const candidates = await d.prisma.scan.findMany({
    where: {
      status: 'running',
      startedAt: { lt: cutoff },
      target: { platform: { in: platforms } },
    },
    select: { id: true },
  });

  const reaped: string[] = [];
  for (const { id } of candidates) {
    if (VIVO.has(await d.jobState(id))) continue;

    // Condicional: se o scan terminou ou foi cancelado nesse meio tempo, nada muda.
    const done = await d.prisma.scan.updateMany({
      where: { id, status: 'running' },
      data: { status: 'failed', error: ORPHAN_ERROR, finishedAt: now },
    });
    if (done.count === 0) continue;

    await d.prisma.task.updateMany({
      where: { scanId: id, status: { in: ['pending', 'running'] } },
      data: { status: 'failed', error: 'interrompida junto com o scan' },
    });
    reaped.push(id);
  }
  return reaped;
}
