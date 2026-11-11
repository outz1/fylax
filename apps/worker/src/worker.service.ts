import { readFileSync } from 'node:fs';
import { Injectable, Logger, type OnApplicationShutdown, type OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { SCAN_QUEUES, type ScanJob, type ScanQueueName } from '@fylax/core';
import { PrismaAssetSink, PrismaAuditSink } from '@fylax/db';
import { ScopedHttpClient, ScopedNmap } from '@fylax/http';
import { Queue, Worker, redisConnection, type Job } from '@fylax/queue';
import { ScopeGuard, ScopeResolver, SystemDnsResolver } from '@fylax/scope';
import { ScanProcessor } from './processor';
import { reapOrphanedScans, type JobState } from './reaper';
import { CHECKS } from './registry';

const csv = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

function readOvpn(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

/** Filas que um worker pode consumir hoje. A de bounty entra na fase 6, com firewall próprio. */
const QUEUES: readonly ScanQueueName[] = [SCAN_QUEUES.lab, SCAN_QUEUES.local];

function queueFromEnv(): ScanQueueName {
  const wanted = process.env.WORKER_QUEUE ?? SCAN_QUEUES.lab;
  const queue = QUEUES.find((q) => q === wanted);
  if (!queue) throw new Error(`WORKER_QUEUE inválida: "${wanted}" (use ${QUEUES.join(' ou ')})`);
  return queue;
}

/** Consome uma fila (lab ou local): um scan por vez (concurrency 1). */
@Injectable()
export class WorkerService implements OnModuleInit, OnApplicationShutdown {
  private readonly log = new Logger('worker');
  private readonly prisma = new PrismaClient();
  private worker?: Worker<ScanJob>;
  private queueClient?: Queue<ScanJob>;
  private reaperTimer?: NodeJS.Timeout;

  onModuleInit(): void {
    const queue = queueFromEnv();
    if (process.env.FYLAX_WORKER_IN_VPN !== '1') {
      this.log.warn(
        'fora do namespace do vpn: sem kill switch de rede. Scans reais devem rodar pelo worker-lab do compose (docker compose --profile worker up -d).',
      );
    }

    const audit = new PrismaAuditSink(this.prisma);
    const guard = new ScopeGuard(
      new ScopeResolver({
        dns: new SystemDnsResolver(),
        extraBlockedCidrs: csv(process.env.FYLAX_LAN_CIDRS),
      }),
      audit,
    );
    const processor = new ScanProcessor({
      prisma: this.prisma,
      checks: CHECKS,
      queue,
      env: { LAB_CIDRS: process.env.LAB_CIDRS, OVPN_FILE: process.env.OVPN_FILE },
      readOvpn,
      assetSinkFor: (scanId) => new PrismaAssetSink(this.prisma, scanId),
      makeHttp: ({ scanId, profile, context }) =>
        new ScopedHttpClient({
          guard,
          context,
          profile,
          audit,
          scanId,
          assets: new PrismaAssetSink(this.prisma, scanId),
        }),
      makeNmap: ({ scanId, context }) => new ScopedNmap({ guard, context, audit, scanId }),
    });

    const connection = redisConnection(process.env.REDIS_URL ?? 'redis://127.0.0.1:6379');
    this.worker = new Worker<ScanJob>(
      queue,
      async (job: Job<ScanJob>) => {
        // attemptsStarted > 1: o BullMQ reentregou o job (worker caiu no meio); retoma o scan.
        const outcome = await processor.process(job.data.scanId, {
          resume: job.attemptsStarted > 1,
        });
        this.log.log(`scan ${job.data.scanId}: ${outcome}`);
        return outcome;
      },
      { connection, concurrency: 1 },
    );
    this.worker.on('failed', (job, err) => this.log.error(`job ${job?.id} falhou: ${err.message}`));
    this.log.log(`consumindo a fila ${queue}`);

    // Reaper: scan "running" cujo job sumiu da fila (worker morto, Redis limpo) seria órfão para sempre.
    const queueClient = new Queue<ScanJob>(queue, { connection });
    this.queueClient = queueClient;
    const sweep = () =>
      reapOrphanedScans({
        prisma: this.prisma,
        queue,
        jobState: async (scanId) => {
          const job = await queueClient.getJob(scanId);
          return job ? ((await job.getState()) as JobState) : 'missing';
        },
      }).then(
        (ids) => {
          if (ids.length > 0) this.log.warn(`scans órfãos encerrados: ${ids.join(', ')}`);
        },
        (e: unknown) =>
          this.log.error(`reaper falhou: ${e instanceof Error ? e.message : String(e)}`),
      );
    setTimeout(() => void sweep(), 30_000).unref();
    this.reaperTimer = setInterval(() => void sweep(), 5 * 60_000);
    this.reaperTimer.unref();
  }

  async onApplicationShutdown(): Promise<void> {
    if (this.reaperTimer) clearInterval(this.reaperTimer);
    await this.queueClient?.close();
    await this.worker?.close();
    await this.prisma.$disconnect();
  }
}
