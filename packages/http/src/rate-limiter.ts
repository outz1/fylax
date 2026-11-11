interface Bucket {
  tokens: number;
  rate: number;
  last: number;
}

/** Token bucket por chave (host). A taxa efetiva só pode diminuir, nunca aumentar. */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
  ) {}

  async acquire(key: string, ratePerSecond: number): Promise<void> {
    const rate = Math.max(ratePerSecond, 0.001);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: Math.max(1, Math.min(rate, 10)), rate, last: this.now() };
      this.buckets.set(key, bucket);
    }
    bucket.rate = Math.min(bucket.rate, rate);

    for (;;) {
      const t = this.now();
      bucket.tokens = Math.min(
        Math.max(1, Math.min(bucket.rate, 10)),
        bucket.tokens + ((t - bucket.last) / 1000) * bucket.rate,
      );
      bucket.last = t;
      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return;
      }
      await this.sleep(Math.ceil(((1 - bucket.tokens) / bucket.rate) * 1000));
    }
  }
}
