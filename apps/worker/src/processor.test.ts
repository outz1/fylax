import { PrismaClient } from '@prisma/client';
import { afterAll, describe, expect, it } from 'vitest';
import type {
  Check,
  CheckModule,
  Finding,
  ScanProfile,
  NmapRequest,
  NmapResult,
  ScopedHttpClient,
  ScopedNmap,
  ScopedRequest,
  TargetPlatform,
} from '@fylax/core';
import { PrismaAssetSink } from '@fylax/db';
import type { ScopeContext } from '@fylax/scope';
import { ScanProcessor, type HttpFactoryArgs, type ProcessorDeps } from './processor';

const prisma = new PrismaClient();
const sufixo = `${process.pid}-${Date.now()}`;
const LAB_ENV = { LAB_CIDRS: '10.250.0.0/24' };
let contador = 0;

class FakeHttp implements ScopedHttpClient {
  readonly requests: ScopedRequest[] = [];
  async request(req: ScopedRequest) {
    this.requests.push(req);
    return { status: 200, headers: {}, body: '', bytes: 0 };
  }
}

class FakeNmap implements ScopedNmap {
  readonly calls: NmapRequest[] = [];
  async scan(req: NmapRequest): Promise<NmapResult> {
    this.calls.push(req);
    return { hosts: [], durationMs: 1 };
  }
}

function check(id: string, run: Check['run'] = async () => [], over: Partial<Check> = {}): Check {
  return {
    id,
    module: id.split('.')[0] as CheckModule,
    severity: 'info',
    references: [],
    appliesTo: () => true,
    run,
    ...over,
  };
}

function finding(checkId: string, dedupKey = 'k1'): Finding {
  return {
    checkId,
    title: 't',
    severity: 'info',
    confidence: 'high',
    asset: 'a',
    description: 'd',
    evidence: { x: 1 },
    reproduction: ['passo'],
    references: [],
    dedupKey,
  };
}

function setup(checks: Check[], over: Partial<ProcessorDeps> = {}) {
  const http = new FakeHttp();
  const nmap = new FakeNmap();
  const factoryCalls: HttpFactoryArgs[] = [];
  const processor = new ScanProcessor({
    prisma,
    checks,
    queue: 'scans-lab',
    env: LAB_ENV,
    readOvpn: () => undefined,
    makeHttp: (args) => {
      factoryCalls.push(args);
      return http;
    },
    makeNmap: () => nmap,
    assetSinkFor: (scanId) => new PrismaAssetSink(prisma, scanId),
    cancelPollMs: 20,
    ...over,
  });
  return { processor, http, nmap, factoryCalls };
}

async function programa(automation: 'allowed' | 'unspecified' | 'forbidden') {
  return prisma.program.create({
    data: {
      platform: 'hackerone',
      name: `proc-${automation}-${contador++}-${sufixo}`,
      briefUrl: 'https://hackerone.com/exemplo',
      inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
      outOfScope: [],
      rules: { automation, maxRequestsPerSecond: 5, testAccountsOnly: false, forbidden: [] },
      reviewedAt: new Date(),
    },
  });
}

async function novoScan(
  over: {
    platform?: TargetPlatform;
    profile?: ScanProfile;
    kind?: 'host' | 'url';
    programId?: string;
    confirmed?: boolean;
  } = {},
) {
  const platform = over.platform ?? 'htb';
  const target = await prisma.target.create({
    data: {
      kind: over.kind ?? 'host',
      value: `proc-${contador++}-${sufixo}.invalid`,
      platform,
      programId: over.programId ?? null,
    },
  });
  const scan = await prisma.scan.create({
    data: {
      targetId: target.id,
      profile: over.profile ?? 'standard',
      confirmedAt: over.confirmed ? new Date() : null,
    },
  });
  return scan.id;
}

const status = async (id: string) =>
  (await prisma.scan.findUniqueOrThrow({ where: { id } })).status;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

afterAll(async () => {
  const targets = await prisma.target.findMany({ where: { value: { contains: sufixo } } });
  const scans = await prisma.scan.findMany({
    where: { targetId: { in: targets.map((t) => t.id) } },
  });
  const ids = scans.map((s) => s.id);
  await prisma.auditLog.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.finding.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.asset.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.task.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.scan.deleteMany({ where: { id: { in: ids } } });
  await prisma.target.deleteMany({ where: { id: { in: targets.map((t) => t.id) } } });
  await prisma.program.deleteMany({ where: { name: { contains: sufixo } } });
  await prisma.$disconnect();
});

describe('ciclo de vida', () => {
  it('9. scan de lab: queued -> done, com tasks, findings e assets persistidos', async () => {
    const id = await novoScan();
    const { processor } = setup([
      check('recon.um', async (ctx) => {
        await ctx.emitAsset({ type: 'port', data: { port: 80, state: 'open' } });
        return [finding('recon.um', 'k1')];
      }),
      check('web.dois', async () => [finding('web.dois', 'k2')]),
    ]);

    expect(await processor.process(id)).toBe('done');

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id }, include: { tasks: true } });
    expect(scan.status).toBe('done');
    expect(scan.startedAt).not.toBeNull();
    expect(scan.finishedAt).not.toBeNull();
    expect(scan.error).toBeNull();
    expect(scan.tasks.map((t) => [t.module, t.status, t.attempts]).sort()).toEqual([
      ['recon', 'done', 1],
      ['web', 'done', 1],
    ]);
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(2);
    expect(await prisma.asset.count({ where: { scanId: id } })).toBe(1);
  });

  it('10. não reexecuta scan finalizado; reentrega (resume) não duplica asset nem finding', async () => {
    const id = await novoScan();
    let execucoes = 0;
    const { processor } = setup([
      check('recon.um', async (ctx) => {
        execucoes++;
        await ctx.emitAsset({ type: 'port', data: { port: 22, state: 'open' } });
        return [finding('recon.um', 'k1')];
      }),
    ]);

    expect(await processor.process(id)).toBe('done');
    expect(await processor.process(id)).toBe('skipped'); // já done: nada roda
    expect(execucoes).toBe(1);

    // Simula o worker ter caído no meio e o job ter sido reentregue.
    await prisma.scan.update({ where: { id }, data: { status: 'running' } });
    expect(await processor.process(id, { resume: true })).toBe('done');
    expect(execucoes).toBe(2);
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(1);
    expect(await prisma.asset.count({ where: { scanId: id } })).toBe(1);
    const task = await prisma.task.findFirstOrThrow({ where: { scanId: id } });
    expect(task.attempts).toBe(2);

    // Sem resume, um scan running (de outro worker) não é reivindicado.
    await prisma.scan.update({ where: { id }, data: { status: 'running' } });
    expect(await processor.process(id)).toBe('skipped');
  });

  it('scan inexistente é ignorado', async () => {
    const { processor } = setup([]);
    expect(await processor.process('00000000-0000-4000-8000-000000000000')).toBe('skipped');
  });

  it('assets emitidos ficam visíveis para os checks seguintes, e o alvo entra como asset de partida', async () => {
    const id = await novoScan();
    const vistos: string[] = [];
    const { processor } = setup([
      check('recon.a', async (ctx) => {
        await ctx.emitAsset({ type: 'port', data: { port: 443, marker: 'A' } });
        return [];
      }),
      check(
        'recon.b',
        async (ctx) => {
          vistos.push(
            ...ctx.assets.map((a) => String(a.data.marker ?? (a.data.target ? 'alvo' : '?'))),
          );
          return [];
        },
        { appliesTo: (a) => a.data.marker === 'A' },
      ),
      check('recon.c', async () => [], { appliesTo: (a) => a.data.target === true }),
    ]);
    expect(await processor.process(id)).toBe('done');
    expect(vistos).toEqual(['alvo', 'A']);
    expect(await prisma.asset.count({ where: { scanId: id } })).toBe(1); // o alvo não é persistido
  });

  it('check que não se aplica a nenhum asset não roda e a task fica skipped', async () => {
    const id = await novoScan();
    let rodou = false;
    const { processor } = setup([
      check(
        'web.nada',
        async () => {
          rodou = true;
          return [];
        },
        { appliesTo: () => false },
      ),
    ]);
    expect(await processor.process(id)).toBe('done');
    expect(rodou).toBe(false);
    expect((await prisma.task.findFirstOrThrow({ where: { scanId: id } })).status).toBe('skipped');
  });
});

describe('escopo e confirmação (falha fechada)', () => {
  it('12. sem allowlist de lab: failed, nenhum check roda e nada vai para a rede', async () => {
    const id = await novoScan();
    let rodou = false;
    const { processor, factoryCalls, http } = setup(
      [
        check('recon.x', async () => {
          rodou = true;
          return [];
        }),
      ],
      { env: {} },
    );

    expect(await processor.process(id)).toBe('failed');

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id } });
    expect(scan.status).toBe('failed');
    expect(scan.error).toMatch(/sem allowlist de lab/);
    expect(scan.finishedAt).not.toBeNull();
    expect(rodou).toBe(false);
    expect(factoryCalls).toHaveLength(0);
    expect(http.requests).toHaveLength(0);
    expect(
      await prisma.auditLog.count({
        where: { scanId: id, action: { in: ['http.request', 'tool.exec'] } },
      }),
    ).toBe(0);
    expect(await prisma.task.count({ where: { scanId: id } })).toBe(0);
  });

  it('lab local roda só na fila scans-local; htb e thm só na scans-lab', async () => {
    const local = await novoScan({ platform: 'local' });
    const htb = await novoScan({ platform: 'htb' });
    let rodou = 0;
    const checks = [
      check('recon.x', async () => {
        rodou++;
        return [];
      }),
    ];

    // worker da VPN (scans-lab) recusa o scan local
    expect(await setup(checks, { queue: 'scans-lab' }).processor.process(local)).toBe('failed');
    expect((await prisma.scan.findUniqueOrThrow({ where: { id: local } })).error).toMatch(
      /plataforma "local" não é atendida pela fila scans-lab/,
    );
    expect(rodou).toBe(0);

    // worker local (scans-local) recusa o scan de HTB
    expect(await setup(checks, { queue: 'scans-local' }).processor.process(htb)).toBe('failed');
    expect((await prisma.scan.findUniqueOrThrow({ where: { id: htb } })).error).toMatch(
      /plataforma "htb" não é atendida pela fila scans-local/,
    );

    // e cada um executa o seu
    const local2 = await novoScan({ platform: 'local' });
    expect(await setup(checks, { queue: 'scans-local' }).processor.process(local2)).toBe('done');
    expect(rodou).toBe(1);
  });

  it('plataforma de outra fila não executa neste worker', async () => {
    const prog = await programa('allowed');
    const id = await novoScan({ platform: 'bounty', kind: 'url', programId: prog.id });
    let rodou = false;
    const { processor } = setup([
      check('recon.x', async () => {
        rodou = true;
        return [];
      }),
    ]);
    expect(await processor.process(id)).toBe('failed');
    expect((await prisma.scan.findUniqueOrThrow({ where: { id } })).error).toMatch(
      /não é atendida pela fila scans-lab/,
    );
    expect(rodou).toBe(false);
  });

  it('11. automation unspecified: sem confirm falha; com confirm executa com o escopo do programa', async () => {
    const prog = await programa('unspecified');
    const semConfirm = await novoScan({ platform: 'bounty', kind: 'url', programId: prog.id });
    let rodou = 0;
    const { processor, factoryCalls } = setup(
      [
        check('recon.x', async () => {
          rodou++;
          return [];
        }),
      ],
      { queue: 'scans-bounty' },
    );

    expect(await processor.process(semConfirm)).toBe('failed');
    expect((await prisma.scan.findUniqueOrThrow({ where: { id: semConfirm } })).error).toMatch(
      /confirmação humana ausente/,
    );
    expect(rodou).toBe(0);
    expect(factoryCalls).toHaveLength(0);

    const comConfirm = await novoScan({
      platform: 'bounty',
      kind: 'url',
      programId: prog.id,
      confirmed: true,
    });
    expect(await processor.process(comConfirm)).toBe('done');
    expect(rodou).toBe(1);
    const ctx = factoryCalls[0]?.context as Extract<ScopeContext, { mode: 'program' }>;
    expect(ctx.mode).toBe('program');
    expect(ctx.program.rules.automation).toBe('unspecified');
  });

  it('programa com dados inválidos no banco falha o scan', async () => {
    const prog = await programa('allowed');
    await prisma.program.update({
      where: { id: prog.id },
      data: { inScope: [{ kind: 'cidr', value: '0.0.0.0/0' }] },
    });
    const id = await novoScan({ platform: 'bounty', kind: 'url', programId: prog.id });
    const { processor } = setup([], { queue: 'scans-bounty' });
    expect(await processor.process(id)).toBe('failed');
    expect((await prisma.scan.findUniqueOrThrow({ where: { id } })).error).toMatch(
      /escopo inválido/,
    );
  });

  it('7. perfil passive e automation forbidden: só checks passivos, com request sempre passivo', async () => {
    const ativo = check('recon.ativo', async () => [finding('recon.ativo', 'a')]);
    const passivo = check(
      'recon.passivo',
      async (ctx) => {
        await ctx.http.request({ method: 'GET', url: 'https://x.exemplo.com/' });
        return [finding('recon.passivo', 'p')];
      },
      { passive: true },
    );

    // perfil passive
    const a = await novoScan({ profile: 'passive' });
    const s1 = setup([ativo, passivo]);
    expect(await s1.processor.process(a)).toBe('done');
    expect((await prisma.finding.findMany({ where: { scanId: a } })).map((f) => f.checkId)).toEqual(
      ['recon.passivo'],
    );
    expect(s1.http.requests.map((r) => r.passive)).toEqual([true]);

    // programa com automation forbidden, perfil standard
    const prog = await programa('forbidden');
    const b = await novoScan({ platform: 'bounty', kind: 'url', programId: prog.id });
    const s2 = setup([ativo, passivo], { queue: 'scans-bounty' });
    expect(await s2.processor.process(b)).toBe('done');
    expect((await prisma.finding.findMany({ where: { scanId: b } })).map((f) => f.checkId)).toEqual(
      ['recon.passivo'],
    );
    expect(s2.http.requests.map((r) => r.passive)).toEqual([true]);

    // perfil standard em lab: os dois rodam
    const c = await novoScan();
    const s3 = setup([ativo, passivo]);
    expect(await s3.processor.process(c)).toBe('done');
    expect(await prisma.finding.count({ where: { scanId: c } })).toBe(2);
  });
});

describe('nmap e perfil no contexto do check', () => {
  it('o check ativo recebe o profile do scan e o nmap; o passivo recebe um nmap que recusa', async () => {
    let perfil: string | undefined;
    const ativo = check('recon.ativo', async (ctx) => {
      perfil = ctx.profile;
      await ctx.nmap.scan({ host: '10.250.0.10', profile: 'standard' });
      return [];
    });
    const passivo = check(
      'recon.passivo',
      async (ctx) => {
        await ctx.nmap.scan({ host: '10.250.0.10', profile: 'standard' });
        return [];
      },
      { passive: true },
    );

    const id = await novoScan({ profile: 'deep' });
    const s = setup([ativo, passivo]);
    expect(await s.processor.process(id)).toBe('done');
    expect(perfil).toBe('deep');
    expect(s.nmap.calls).toHaveLength(1); // só o ativo chegou ao nmap
    const task = await prisma.task.findFirstOrThrow({ where: { scanId: id } });
    expect(task.status).toBe('failed');
    expect(task.error).toContain('recon.passivo: nmap não roda em perfil ou check passivo');
  });

  it('em perfil passive nenhum check ativo roda, então o nmap nunca é chamado', async () => {
    const id = await novoScan({ profile: 'passive' });
    const s = setup([
      check('recon.ativo', async (ctx) => {
        await ctx.nmap.scan({ host: 'x', profile: 'standard' });
        return [];
      }),
    ]);
    expect(await s.processor.process(id)).toBe('done');
    expect(s.nmap.calls).toHaveLength(0);
  });

  it('programa com automation forbidden: o nmap é recusado mesmo num check marcado como passivo ou não', async () => {
    const prog = await programa('forbidden');
    const id = await novoScan({ platform: 'bounty', kind: 'url', programId: prog.id });
    const s = setup(
      [
        check('recon.ativo', async (ctx) => {
          await ctx.nmap.scan({ host: 'x', profile: 'standard' });
          return [];
        }),
      ],
      { queue: 'scans-bounty' },
    );
    expect(await s.processor.process(id)).toBe('done');
    expect(s.nmap.calls).toHaveLength(0); // check ativo nem foi selecionado
  });
});

describe('isolamento de erro e timeout', () => {
  it('13. um check que lança vira Task.error; os demais continuam e o scan termina done', async () => {
    const id = await novoScan();
    const { processor } = setup([
      check('recon.quebra', async () => {
        throw new Error('falha simulada');
      }),
      check('recon.ok', async () => [finding('recon.ok')]),
      check('web.ok', async () => [finding('web.ok', 'w')]),
    ]);
    expect(await processor.process(id)).toBe('done');

    const tasks = await prisma.task.findMany({ where: { scanId: id }, orderBy: { module: 'asc' } });
    const recon = tasks.find((t) => t.module === 'recon');
    expect(recon?.status).toBe('failed');
    expect(recon?.error).toContain('recon.quebra: falha simulada');
    expect(tasks.find((t) => t.module === 'web')?.status).toBe('done');
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(2);
  });

  it('check que estoura o timeout vira erro e o próximo check roda', async () => {
    const id = await novoScan();
    const { processor } = setup(
      [
        check('recon.trava', () => new Promise<Finding[]>(() => undefined)),
        check('recon.depois', async () => [finding('recon.depois')]),
      ],
      { checkTimeoutMs: 50 },
    );
    expect(await processor.process(id)).toBe('done');
    const task = await prisma.task.findFirstOrThrow({ where: { scanId: id } });
    expect(task.status).toBe('failed');
    expect(task.error).toMatch(/recon\.trava: timeout de 50 ms/);
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(1);
  });

  it('finding fora da convenção do módulo é rejeitado e vira erro da task', async () => {
    const id = await novoScan();
    const { processor } = setup([check('recon.errado', async () => [finding('web.xss')])]);
    expect(await processor.process(id)).toBe('done');
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(0);
    expect((await prisma.task.findFirstOrThrow({ where: { scanId: id } })).error).toMatch(
      /fora do módulo recon/,
    );
  });
});

describe('cancelamento', () => {
  it('14. cancel interrompe o check em curso e nenhum passo novo começa', async () => {
    const id = await novoScan();
    let iniciou = false;
    let depois = false;
    const { processor } = setup([
      check(
        'recon.lento',
        (ctx) =>
          new Promise<Finding[]>((_, reject) => {
            iniciou = true;
            ctx.signal?.addEventListener('abort', () => reject(new Error('abortado')));
          }),
      ),
      check('recon.depois', async () => {
        depois = true;
        return [];
      }),
      check('web.depois', async () => {
        depois = true;
        return [];
      }),
    ]);

    const rodando = processor.process(id);
    while (!iniciou) await sleep(10);
    await prisma.scan.update({
      where: { id },
      data: { status: 'canceled', finishedAt: new Date() },
    });

    expect(await rodando).toBe('canceled');
    expect(depois).toBe(false);
    expect(await status(id)).toBe('canceled'); // o worker não sobrescreve o cancelamento
    const tasks = await prisma.task.findMany({ where: { scanId: id } });
    expect(tasks.every((t) => t.status === 'skipped')).toBe(true);
    expect(tasks.every((t) => t.error === 'scan cancelado')).toBe(true);
  });

  it('14b. cancel entre dois checks é detectado sem esperar o poll: o próximo check nem começa', async () => {
    const id = await novoScan();
    let comecou = false;
    const { processor } = setup(
      [
        check('recon.primeiro', async () => {
          // Cancela e termina normalmente: nenhum check está em curso quando o cancel vale.
          await prisma.scan.update({
            where: { id },
            data: { status: 'canceled', finishedAt: new Date() },
          });
          return [];
        }),
        check('recon.segundo', async () => {
          comecou = true;
          return [];
        }),
      ],
      { cancelPollMs: 3_600_000 }, // o poll nunca dispara: só a leitura direta pode pegar
    );

    expect(await processor.process(id)).toBe('canceled');
    expect(comecou).toBe(false);
    expect(await status(id)).toBe('canceled');
  });

  it('scan cancelado antes de começar não executa', async () => {
    const id = await novoScan();
    await prisma.scan.update({ where: { id }, data: { status: 'canceled' } });
    let rodou = false;
    const { processor } = setup([
      check('recon.x', async () => {
        rodou = true;
        return [];
      }),
    ]);
    expect(await processor.process(id)).toBe('skipped');
    expect(rodou).toBe(false);
  });
});
