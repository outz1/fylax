import { describe, expect, it } from 'vitest';
import { NmapError, SpawnNmapRunner } from './nmap-runner';

// Usa o próprio Node como "binário" para testar o executor sem depender do nmap instalado.
const node = new SpawnNmapRunner(process.execPath);
const base = { timeoutMs: 10_000, maxOutputBytes: 1_000_000 };

describe('SpawnNmapRunner', () => {
  it('captura stdout, stderr e o código de saída', async () => {
    const out = await node.run({
      ...base,
      args: ['-e', "process.stdout.write('<x/>'); process.stderr.write('aviso'); process.exit(3)"],
    });
    expect(out).toEqual({ stdout: '<x/>', stderr: 'aviso', exitCode: 3 });
  });

  it('não usa shell: metacaracteres chegam como texto', async () => {
    const out = await node.run({
      ...base,
      args: ['-e', 'process.stdout.write(process.argv[1])', '; echo VAZOU && $(whoami)'],
    });
    expect(out.stdout).toBe('; echo VAZOU && $(whoami)');
  });

  it('timeout encerra o processo e vira NmapError', async () => {
    const t0 = Date.now();
    await expect(
      node.run({ ...base, timeoutMs: 200, args: ['-e', 'setTimeout(() => {}, 60000)'] }),
    ).rejects.toThrow(/tempo limite/);
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it('AbortSignal encerra o processo em curso', async () => {
    const controller = new AbortController();
    const rodando = node.run({
      ...base,
      signal: controller.signal,
      args: ['-e', 'setTimeout(() => {}, 60000)'],
    });
    setTimeout(() => controller.abort(), 100);
    await expect(rodando).rejects.toThrow(/cancelada/);
  });

  it('signal já abortado nem inicia o processo', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      node.run({ ...base, signal: controller.signal, args: ['-e', ''] }),
    ).rejects.toThrow(/cancelada/);
  });

  it('saída acima do limite é cortada com erro', async () => {
    await expect(
      node.run({
        ...base,
        maxOutputBytes: 1000,
        args: ['-e', "process.stdout.write('A'.repeat(100000))"],
      }),
    ).rejects.toThrow(/excedeu o limite/);
  });

  it('binário inexistente vira NmapError claro', async () => {
    await expect(
      new SpawnNmapRunner('binario-que-nao-existe-xyz').run({ ...base, args: [] }),
    ).rejects.toBeInstanceOf(NmapError);
    await expect(
      new SpawnNmapRunner('binario-que-nao-existe-xyz').run({ ...base, args: [] }),
    ).rejects.toThrow(/não encontrado/);
  });
});
