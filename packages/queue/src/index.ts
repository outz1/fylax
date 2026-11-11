import { Queue, type ConnectionOptions } from 'bullmq';
import {
  queueForPlatform,
  type ScanJob,
  type ScanQueueName,
  type TargetPlatform,
} from '@fylax/core';

/** Converte REDIS_URL (redis:// ou rediss://) nas opções de conexão do BullMQ. */
export function redisConnection(url: string): ConnectionOptions {
  const u = new URL(url);
  if (u.protocol !== 'redis:' && u.protocol !== 'rediss:') {
    throw new Error(`REDIS_URL inválida: esquema ${u.protocol}`);
  }
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 6379,
    ...(u.username ? { username: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    ...(u.pathname.length > 1 ? { db: Number(u.pathname.slice(1)) } : {}),
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
  };
}

/** Produtor de jobs de scan. A API e a CLI enfileiram; só o worker da fila executa. */
export interface ScanEnqueuer {
  /** Enfileira (idempotente: o jobId é o scanId) e devolve a fila usada. */
  enqueue(scanId: string, platform: TargetPlatform): Promise<ScanQueueName>;
  /** Remove um job ainda não iniciado (cancelamento). */
  remove(scanId: string, platform: TargetPlatform): Promise<void>;
  close(): Promise<void>;
}

export const SCAN_ENQUEUER = Symbol('SCAN_ENQUEUER');

export class BullScanEnqueuer implements ScanEnqueuer {
  private readonly queues = new Map<ScanQueueName, Queue<ScanJob>>();

  constructor(private readonly connection: ConnectionOptions) {}

  private queue(name: ScanQueueName): Queue<ScanJob> {
    let q = this.queues.get(name);
    if (!q) {
      q = new Queue<ScanJob>(name, {
        connection: this.connection,
        defaultJobOptions: {
          attempts: 1,
          removeOnComplete: { age: 24 * 3600 },
          removeOnFail: { age: 7 * 24 * 3600 },
        },
      });
      this.queues.set(name, q);
    }
    return q;
  }

  async enqueue(scanId: string, platform: TargetPlatform): Promise<ScanQueueName> {
    const name = queueForPlatform(platform);
    // jobId = scanId: enfileirar duas vezes o mesmo scan não duplica a execução.
    await this.queue(name).add('scan', { scanId }, { jobId: scanId });
    return name;
  }

  async remove(scanId: string, platform: TargetPlatform): Promise<void> {
    const job = await this.queue(queueForPlatform(platform)).getJob(scanId);
    if (job && (await job.isWaiting())) await job.remove();
  }

  async close(): Promise<void> {
    await Promise.all([...this.queues.values()].map((q) => q.close()));
    this.queues.clear();
  }

  /** Permite que o Nest feche as conexões ao encerrar (hook de ciclo de vida). */
  onModuleDestroy(): Promise<void> {
    return this.close();
  }
}

export { Queue, Worker, type Job } from 'bullmq';
