import { queueForPlatform, type ScanQueueName, type TargetPlatform } from '@fylax/core';
import type { ScanEnqueuer } from '@fylax/queue';

/** Enfileirador falso: os testes da API não dependem do Redis. */
export class FakeEnqueuer implements ScanEnqueuer {
  readonly enqueued: Array<{ scanId: string; queue: ScanQueueName }> = [];
  readonly removed: string[] = [];

  async enqueue(scanId: string, platform: TargetPlatform): Promise<ScanQueueName> {
    const queue = queueForPlatform(platform);
    this.enqueued.push({ scanId, queue });
    return queue;
  }

  async remove(scanId: string): Promise<void> {
    this.removed.push(scanId);
  }

  async close(): Promise<void> {}
}
