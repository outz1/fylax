import { describe, expect, it } from 'vitest';
import { RateLimiter } from './rate-limiter';

function clock() {
  let t = 0;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    advance: (ms: number) => {
      t += ms;
    },
    sleeps,
  };
}

describe('RateLimiter', () => {
  it('uma requisição passa sem espera; as seguintes esperam 1/taxa', async () => {
    const c = clock();
    const rl = new RateLimiter(c.now, c.sleep);
    await rl.acquire('a', 2);
    await rl.acquire('a', 2);
    await rl.acquire('a', 2);
    expect(c.sleeps.length).toBeGreaterThan(0);
    expect(c.sleeps.every((ms) => ms <= 500)).toBe(true);
  });

  it('hosts diferentes têm buckets independentes', async () => {
    const c = clock();
    const rl = new RateLimiter(c.now, c.sleep);
    await rl.acquire('a', 1);
    await rl.acquire('b', 1);
    expect(c.sleeps).toEqual([]);
  });

  it('tempo parado recarrega tokens', async () => {
    const c = clock();
    const rl = new RateLimiter(c.now, c.sleep);
    await rl.acquire('a', 1);
    c.advance(1500);
    await rl.acquire('a', 1);
    expect(c.sleeps).toEqual([]);
  });

  it('a taxa efetiva só diminui', async () => {
    const c = clock();
    const rl = new RateLimiter(c.now, c.sleep);
    await rl.acquire('a', 1);
    await rl.acquire('a', 100); // tentativa de aumentar é ignorada
    expect(c.sleeps).toEqual([1000]);
  });

  it('taxa menor que 1 req/s espera mais de 1s', async () => {
    const c = clock();
    const rl = new RateLimiter(c.now, c.sleep);
    await rl.acquire('a', 0.5);
    await rl.acquire('a', 0.5);
    expect(c.sleeps).toEqual([2000]);
  });
});
