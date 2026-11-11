import { describe, expect, it } from 'vitest';
import type { AuditEntry, AuditSink } from '@fylax/core';
import { ScopeGuard, ScopeResolver, ScopeViolationError, type ScopeContext } from '@fylax/scope';
import { FakeDns, MemoryAudit, NOW, programCtx } from '@fylax/scope/testing';
import { ScopedNmap } from './nmap';
import { NMAP_PROFILE_TABLE, NmapArgsError } from './nmap-args';
import { NmapError, type NmapRunInput, type NmapRunOutput, type NmapRunner } from './nmap-runner';
import { NmapParseError } from './nmap-xml';

const LAB: ScopeContext = { mode: 'lab', allowlist: ['10.250.0.0/24'] };

const xml = (...hosts: Array<{ ip: string; ports: number[] }>) =>
  `<?xml version="1.0"?><nmaprun>${hosts
    .map(
      (h) =>
        `<host><address addr="${h.ip}" addrtype="ipv4"/><ports>${h.ports
          .map(
            (p) =>
              `<port protocol="tcp" portid="${p}"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.27.2"/></port>`,
          )
          .join('')}</ports></host>`,
    )
    .join('')}</nmaprun>`;

class FakeRunner implements NmapRunner {
  readonly calls: NmapRunInput[] = [];
  constructor(private readonly reply: (i: NmapRunInput) => NmapRunOutput | Error) {}
  async run(input: NmapRunInput): Promise<NmapRunOutput> {
    this.calls.push(input);
    const r = this.reply(input);
    if (r instanceof Error) throw r;
    return r;
  }
}

const ok = (stdout: string): NmapRunOutput => ({ stdout, stderr: '', exitCode: 0 });

function setup(opts: {
  context?: ScopeContext;
  dns?: Record<string, { addresses: string[]; cnames: string[] }>;
  runner: NmapRunner;
  audit?: AuditSink & { entries?: AuditEntry[] };
}) {
  const audit = (opts.audit as MemoryAudit | undefined) ?? new MemoryAudit();
  const dns = new FakeDns(
    opts.dns ?? {
      'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] },
      'multi.exemplo.com': { addresses: ['93.184.216.34', '93.184.216.35'], cnames: [] },
    },
  );
  const guard = new ScopeGuard(new ScopeResolver({ dns, now: () => NOW }), audit);
  const nmap = new ScopedNmap({
    guard,
    context: opts.context ?? LAB,
    audit,
    scanId: 'scan-1',
    runner: opts.runner,
  });
  return { nmap, audit };
}

const argsOf = (r: FakeRunner) => r.calls[0]?.args ?? [];
const targetsOf = (r: FakeRunner) => argsOf(r).slice(argsOf(r).indexOf('--') + 1);

describe('ScopedNmap: escopo', () => {
  it('1. destino bloqueado: ScopeViolationError, o nmap NÃO é executado e só scope.block é gravado', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap, audit } = setup({ runner });

    for (const host of [
      '192.168.1.50',
      '127.0.0.1',
      '169.254.169.254',
      '93.184.216.34',
      'sumiu.exemplo.com',
    ]) {
      await expect(nmap.scan({ host, profile: 'standard' }), host).rejects.toBeInstanceOf(
        ScopeViolationError,
      );
    }
    expect(runner.calls).toHaveLength(0);
    expect(audit.actions().every((a) => a === 'scope.block')).toBe(true);
  });

  it('programa fora do inScope e com automation forbidden: bloqueado, nmap não roda', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const fora = setup({ runner, context: programCtx({}) });
    await expect(
      fora.nmap.scan({ host: '93.184.216.34', profile: 'standard' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);

    const proibido = setup({
      runner,
      context: programCtx({ rules: { automation: 'forbidden' } }),
    });
    await expect(
      proibido.nmap.scan({ host: 'box.exemplo.com', profile: 'standard' }),
    ).rejects.toThrow(/proíbe automação/);
    expect(runner.calls).toHaveLength(0);
  });

  it('3. o nmap recebe IPs, nunca o nome; host com vários IPs gera um alvo por IP', async () => {
    const runner = new FakeRunner(() =>
      ok(xml({ ip: '93.184.216.34', ports: [80] }, { ip: '93.184.216.35', ports: [] })),
    );
    const { nmap } = setup({
      runner,
      context: programCtx({ inScope: [{ kind: 'host', value: 'multi.exemplo.com' }] }),
    });

    await nmap.scan({ host: 'multi.exemplo.com', profile: 'standard' });

    expect(targetsOf(runner)).toEqual(['93.184.216.34', '93.184.216.35']);
    expect(argsOf(runner).join(' ')).not.toContain('exemplo.com');
  });

  it('IP literal no lab é escaneado', async () => {
    const runner = new FakeRunner(() => ok(xml({ ip: '10.250.0.10', ports: [80] })));
    const { nmap } = setup({ runner });
    const res = await nmap.scan({ host: '10.250.0.10', profile: 'standard' });
    expect(targetsOf(runner)).toEqual(['10.250.0.10']);
    expect(res.hosts).toEqual([
      {
        ip: '10.250.0.10',
        ports: [
          expect.objectContaining({
            port: 80,
            state: 'open',
            service: expect.objectContaining({ product: 'nginx' }),
          }),
        ],
      },
    ]);
  });

  it('descarta host que não foi pedido (defesa em profundidade)', async () => {
    const runner = new FakeRunner(() =>
      ok(xml({ ip: '10.250.0.10', ports: [80] }, { ip: '10.250.0.99', ports: [22] })),
    );
    const { nmap } = setup({ runner });
    const res = await nmap.scan({ host: '10.250.0.10', profile: 'standard' });
    expect(res.hosts.map((h) => h.ip)).toEqual(['10.250.0.10']);
  });
});

describe('ScopedNmap: taxa e portas', () => {
  const rateOf = (r: FakeRunner) => argsOf(r)[argsOf(r).indexOf('--max-rate') + 1];

  it('4. taxa efetiva é o menor entre perfil e escopo; unspecified limita a 1/s', async () => {
    const dns = { 'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } };
    const rate = async (
      rules: Parameters<typeof programCtx>[0]['rules'],
      profile: 'standard' | 'deep',
    ) => {
      const runner = new FakeRunner(() => ok(xml()));
      const { nmap } = setup({ runner, dns, context: programCtx({ rules }) });
      await nmap.scan({ host: 'box.exemplo.com', profile });
      return rateOf(runner);
    };
    expect(await rate({ automation: 'allowed', maxRequestsPerSecond: 5 }, 'standard')).toBe('5');
    expect(await rate({ automation: 'allowed', maxRequestsPerSecond: 500 }, 'standard')).toBe('50');
    expect(await rate({ automation: 'allowed', maxRequestsPerSecond: 500 }, 'deep')).toBe('100');
    expect(await rate({ automation: 'unspecified', maxRequestsPerSecond: 50 }, 'standard')).toBe(
      '1',
    );
  });

  it('escopo com taxa baixa demais para o perfil: erro claro, nenhum tráfego e nenhum tool.exec', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap, audit } = setup({
      runner,
      dns: { 'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } },
      context: programCtx({ rules: { automation: 'allowed', maxRequestsPerSecond: 5 } }),
    });
    await expect(nmap.scan({ host: 'box.exemplo.com', profile: 'deep' })).rejects.toThrow(
      'impraticável a 5 req/s',
    );
    expect(runner.calls).toHaveLength(0);
    expect(audit.actions()).not.toContain('tool.exec');
  });

  it('o host-timeout e o timeout do processo acompanham a taxa efetiva', async () => {
    const dns = { 'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } };
    const lento = new FakeRunner(() => ok(xml()));
    await setup({
      runner: lento,
      dns,
      context: programCtx({ rules: { automation: 'unspecified', maxRequestsPerSecond: 50 } }), // 1 req/s
    }).nmap.scan({ host: 'box.exemplo.com', profile: 'standard' });

    const rapido = new FakeRunner(() => ok(xml()));
    await setup({ runner: rapido }).nmap.scan({ host: '10.250.0.10', profile: 'standard' });

    const hostTimeout = (r: FakeRunner) =>
      Number(argsOf(r)[argsOf(r).indexOf('--host-timeout') + 1]?.replace('s', ''));
    expect(hostTimeout(lento)).toBeGreaterThan(hostTimeout(rapido));
    expect(lento.calls[0]?.timeoutMs).toBe(hostTimeout(lento) * 1000 + 30_000);
    expect(rapido.calls[0]?.timeoutMs).toBe(hostTimeout(rapido) * 1000 + 30_000);
  });

  it('lab: sem teto de escopo, vale o do perfil', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    await setup({ runner }).nmap.scan({ host: '10.250.0.10', profile: 'deep' });
    expect(rateOf(runner)).toBe('100');
  });

  it('6. programa: só as portas do inScope vão para o nmap, no lugar de --top-ports', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap } = setup({
      runner,
      context: programCtx({
        inScope: [{ kind: 'wildcard', value: '*.exemplo.com', ports: [8443, 443] }],
      }),
    });
    await nmap.scan({ host: 'box.exemplo.com', profile: 'deep' });
    expect(argsOf(runner)).not.toContain('--top-ports');
    expect(argsOf(runner)[argsOf(runner).indexOf('-p') + 1]).toBe('443,8443');
  });

  it('outOfScope com portas: perfil com --exclude-ports; com portas explícitas, subtrai', async () => {
    const dns = { 'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } };
    const out = [{ kind: 'host' as const, value: 'box.exemplo.com', ports: [22, 3306] }];

    const r1 = new FakeRunner(() => ok(xml()));
    await setup({ runner: r1, dns, context: programCtx({ outOfScope: out }) }).nmap.scan({
      host: 'box.exemplo.com',
      profile: 'standard',
    });
    expect(argsOf(r1)).not.toContain('--top-ports');
    expect(argsOf(r1)[argsOf(r1).indexOf('-p') + 1]).toBe(NMAP_PROFILE_TABLE.standard.portSpec);
    expect(argsOf(r1)[argsOf(r1).indexOf('--exclude-ports') + 1]).toBe('22,3306');

    const r2 = new FakeRunner(() => ok(xml()));
    await setup({ runner: r2, dns, context: programCtx({ outOfScope: out }) }).nmap.scan({
      host: 'box.exemplo.com',
      profile: 'standard',
      ports: [22, 80, 3306, 443],
    });
    expect(argsOf(r2)).not.toContain('--exclude-ports');
    expect(argsOf(r2)[argsOf(r2).indexOf('-p') + 1]).toBe('80,443');

    // pedir só portas excluídas: nada sobra
    await expect(
      setup({
        runner: new FakeRunner(() => ok(xml())),
        dns,
        context: programCtx({ outOfScope: out }),
      }).nmap.scan({
        host: 'box.exemplo.com',
        profile: 'standard',
        ports: [22],
      }),
    ).rejects.toBeInstanceOf(NmapArgsError);
  });

  it('outOfScope sem portas retira o host inteiro: nmap não roda', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap } = setup({
      runner,
      dns: { 'box.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } },
      context: programCtx({ outOfScope: [{ kind: 'host', value: 'box.exemplo.com' }] }),
    });
    await expect(
      nmap.scan({ host: 'box.exemplo.com', profile: 'standard' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    expect(runner.calls).toHaveLength(0);
  });

  it('o audit do Scope Guard registra o modo portless', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap, audit } = setup({ runner });
    await nmap.scan({ host: '10.250.0.10', profile: 'standard' });
    expect(audit.entries.find((e) => e.action === 'scope.allow')?.detail).toMatchObject({
      portless: true,
    });
  });

  it('portas pedidas só reduzem: interseção com o escopo, e erro se nada sobra', async () => {
    const ctx = programCtx({
      inScope: [{ kind: 'wildcard', value: '*.exemplo.com', ports: [80, 443] }],
    });
    const runner = new FakeRunner(() => ok(xml()));
    await setup({ runner, context: ctx }).nmap.scan({
      host: 'box.exemplo.com',
      profile: 'standard',
      ports: [443, 22],
    });
    expect(argsOf(runner)[argsOf(runner).indexOf('-p') + 1]).toBe('443');

    await expect(
      setup({ runner: new FakeRunner(() => ok(xml())), context: ctx }).nmap.scan({
        host: 'box.exemplo.com',
        profile: 'standard',
        ports: [22, 3306],
      }),
    ).rejects.toBeInstanceOf(NmapArgsError);
  });

  it('lab sem portas no escopo: portas pedidas valem, e senão o perfil decide', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    await setup({ runner }).nmap.scan({
      host: '10.250.0.10',
      profile: 'standard',
      ports: [22, 80],
    });
    expect(argsOf(runner)[argsOf(runner).indexOf('-p') + 1]).toBe('22,80');

    const r2 = new FakeRunner(() => ok(xml()));
    await setup({ runner: r2 }).nmap.scan({ host: '10.250.0.10', profile: 'standard' });
    expect(argsOf(r2)[argsOf(r2).indexOf('-p') + 1]).toBe(NMAP_PROFILE_TABLE.standard.portSpec);
  });

  it('perfil inválido (inclusive "passive") é recusado e o nmap não roda', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const { nmap } = setup({ runner });
    for (const profile of ['passive', 'agressivo', undefined]) {
      await expect(
        nmap.scan({ host: '10.250.0.10', profile: profile as never }),
      ).rejects.toBeInstanceOf(NmapArgsError);
    }
    expect(runner.calls).toHaveLength(0);
  });
});

describe('ScopedNmap: auditoria tool.exec', () => {
  it('7. grava start ANTES de executar e end depois, com argv, IPs e contagem, sem a saída bruta', async () => {
    const order: string[] = [];
    const audit = new MemoryAudit();
    const original = audit.record.bind(audit);
    audit.record = async (e) => {
      order.push(`audit:${e.action}${e.detail.phase ? `:${e.detail.phase}` : ''}`);
      return original(e);
    };
    const runner = new FakeRunner(() => {
      order.push('nmap');
      return ok(xml({ ip: '10.250.0.10', ports: [80, 443] }) + '<!-- SEGREDO-NA-SAIDA -->');
    });
    const { nmap } = setup({ runner, audit });

    await nmap.scan({ host: '10.250.0.10', profile: 'standard' });

    expect(order).toEqual([
      'audit:scope.allow',
      'audit:tool.exec:start',
      'nmap',
      'audit:tool.exec:end',
    ]);
    const [start, end] = audit.entries.filter((e) => e.action === 'tool.exec');
    expect(start?.scanId).toBe('scan-1');
    expect(start?.detail).toMatchObject({
      tool: 'nmap',
      host: '10.250.0.10',
      ips: ['10.250.0.10'],
      profile: 'standard',
      mode: 'lab',
      phase: 'start',
    });
    expect(start?.detail.argv).toEqual(argsOf(runner));
    expect(end?.detail).toMatchObject({ phase: 'end', exitCode: 0, openPorts: 2 });
    expect(typeof end?.detail.durationMs).toBe('number');
    expect(JSON.stringify(audit.entries)).not.toContain('SEGREDO-NA-SAIDA');
  });

  it('fail closed: se gravar o start falhar, o nmap não é iniciado', async () => {
    const runner = new FakeRunner(() => ok(xml()));
    const quebrado: AuditSink = {
      record: async (e) => {
        if (e.action === 'tool.exec') throw new Error('banco fora');
      },
    };
    const { nmap } = setup({ runner, audit: quebrado });
    await expect(nmap.scan({ host: '10.250.0.10', profile: 'standard' })).rejects.toThrow(
      'banco fora',
    );
    expect(runner.calls).toHaveLength(0);
  });

  it('erro do nmap: o end é gravado com o erro e a exceção sobe', async () => {
    const runner = new FakeRunner(() => new NmapError('nmap excedeu o tempo limite'));
    const { nmap, audit } = setup({ runner });
    await expect(nmap.scan({ host: '10.250.0.10', profile: 'standard' })).rejects.toBeInstanceOf(
      NmapError,
    );
    const end = audit.entries.filter((e) => e.action === 'tool.exec').at(-1);
    expect(end?.detail).toMatchObject({
      phase: 'end',
      error: expect.stringContaining('tempo limite'),
    });
  });

  it('código de saída diferente de zero e XML truncado viram erro (nunca "sem portas")', async () => {
    const { nmap } = setup({
      runner: new FakeRunner(() => ({ stdout: '', stderr: 'permission denied', exitCode: 1 })),
    });
    await expect(nmap.scan({ host: '10.250.0.10', profile: 'standard' })).rejects.toThrow(
      /código 1.*permission denied/,
    );

    const cortado = setup({
      runner: new FakeRunner(() =>
        ok('<nmaprun><host><address addr="10.250.0.10" addrtype="ipv4"/>'),
      ),
    });
    await expect(
      cortado.nmap.scan({ host: '10.250.0.10', profile: 'standard' }),
    ).rejects.toBeInstanceOf(NmapParseError);
  });

  it('o signal de cancelamento chega ao executor', async () => {
    const controller = new AbortController();
    const runner = new FakeRunner(() => ok(xml()));
    await setup({ runner }).nmap.scan(
      { host: '10.250.0.10', profile: 'standard' },
      { signal: controller.signal },
    );
    expect(runner.calls[0]?.signal).toBe(controller.signal);
  });
});
