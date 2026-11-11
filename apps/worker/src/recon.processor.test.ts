import { PrismaClient } from '@prisma/client';
import { afterAll, describe, expect, it } from 'vitest';
import type {
  NmapRequest,
  NmapResult,
  ScopedHttpClient,
  ScopedNmap,
  ScopedRequest,
  ScopedResponse,
} from '@fylax/core';
import { createReconChecks } from '@fylax/checks';
import { PrismaAssetSink } from '@fylax/db';
import { ScanProcessor } from './processor';

/**
 * Teste 9 da fase 2: scan de lab queued -> done com os checks de recon REAIS, banco real, nmap e HTTP
 * simulados. Cobre o encadeamento (port-scan emite assets que http-discover e as análises consomem) e
 * a idempotência ao reprocessar.
 */
const prisma = new PrismaClient();
const IP = '10.250.0.77';

const LAB: NmapResult = {
  durationMs: 5,
  hosts: [
    {
      ip: IP,
      ports: [
        {
          port: 80,
          protocol: 'tcp',
          state: 'open',
          reason: 'syn-ack',
          service: {
            name: 'http',
            product: 'nginx',
            version: '1.27.5',
            cpe: ['cpe:/a:igor_sysoev:nginx:1.27.5'],
          },
        },
        {
          port: 443,
          protocol: 'tcp',
          state: 'open',
          reason: 'syn-ack',
          service: { name: 'http', product: 'nginx', cpe: [], tunnel: 'ssl' },
          tls: {
            subject: 'commonName=fixture.invalid',
            issuer: 'commonName=fixture.invalid',
            san: ['fixture.invalid'],
            notBefore: '2020-01-01T00:00:00',
            notAfter: '2020-01-06T00:00:00',
          },
        },
        {
          port: 6379,
          protocol: 'tcp',
          state: 'open',
          reason: 'syn-ack',
          service: { name: 'redis', cpe: [] },
        },
      ],
    },
  ],
};

class FakeNmap implements ScopedNmap {
  readonly calls: NmapRequest[] = [];
  async scan(req: NmapRequest): Promise<NmapResult> {
    this.calls.push(req);
    return LAB;
  }
}

class FakeHttp implements ScopedHttpClient {
  readonly requests: ScopedRequest[] = [];
  async request(req: ScopedRequest): Promise<ScopedResponse> {
    this.requests.push(req);
    if (req.url.startsWith('https://')) {
      const e = new Error('certificado autoassinado') as Error & { code: string };
      e.name = 'TransportError';
      e.code = 'DEPTH_ZERO_SELF_SIGNED_CERT';
      throw e;
    }
    return {
      status: 200,
      headers: { server: 'nginx/1.27.5' },
      body: '<title>Fylax Lab Web</title>',
      bytes: 28,
    };
  }
}

async function novoScan(
  profile: 'passive' | 'standard' | 'deep' = 'standard',
  kind: 'host' | 'url' = 'host',
) {
  const value = kind === 'host' ? IP : `http://${IP}/`;
  // Reaproveita o alvo, como o createScan de verdade faz (unique em tipo, valor e plataforma).
  const target = await prisma.target.upsert({
    where: { kind_value_platform: { kind, value, platform: 'local' } },
    create: { kind, value, platform: 'local' },
    update: {},
  });
  const scan = await prisma.scan.create({ data: { targetId: target.id, profile } });
  return scan.id;
}

function setup() {
  const nmap = new FakeNmap();
  const http = new FakeHttp();
  const processor = new ScanProcessor({
    prisma,
    // "agora" fixo: o certificado de 2020 está vencido, sem depender do relógio da máquina
    checks: createReconChecks({ now: () => new Date('2026-11-11T12:00:00Z') }),
    queue: 'scans-local',
    env: { LAB_CIDRS: '10.250.0.0/24' },
    readOvpn: () => undefined,
    makeHttp: () => http,
    makeNmap: () => nmap,
    assetSinkFor: (id) => new PrismaAssetSink(prisma, id),
    cancelPollMs: 20,
  });
  return { processor, nmap, http };
}

afterAll(async () => {
  const targets = await prisma.target.findMany({ where: { value: { contains: IP } } });
  const scans = await prisma.scan.findMany({
    where: { targetId: { in: targets.map((t) => t.id) } },
  });
  const ids = scans.map((s) => s.id);
  await prisma.finding.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.asset.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.task.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.auditLog.deleteMany({ where: { scanId: { in: ids } } });
  await prisma.scan.deleteMany({ where: { id: { in: ids } } });
  await prisma.target.deleteMany({ where: { id: { in: targets.map((t) => t.id) } } });
  await prisma.$disconnect();
});

describe('recon completo pelo processador', () => {
  it('9. host de lab: queued -> done, com os assets e os findings esperados persistidos', async () => {
    const id = await novoScan('standard');
    const { processor, nmap, http } = setup();

    expect(await processor.process(id)).toBe('done');

    // um nmap só, no perfil standard
    expect(nmap.calls).toEqual([{ host: IP, profile: 'standard' }]);
    // http-discover: porta 80 (HTTP) e 443 (HTTPS, com certificado que não valida)
    expect(http.requests.map((r) => r.url)).toEqual([`http://${IP}/`, `https://${IP}/`]);

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id }, include: { tasks: true } });
    expect(scan).toMatchObject({ status: 'done', error: null });
    expect(scan.tasks).toHaveLength(1);
    expect(scan.tasks[0]).toMatchObject({
      module: 'recon',
      status: 'done',
      attempts: 1,
      error: null,
    });

    const assets = await prisma.asset.findMany({ where: { scanId: id } });
    const count = (type: string) => assets.filter((a) => a.type === type).length;
    expect(count('port')).toBe(3);
    expect(count('service')).toBe(3);
    expect(count('url')).toBe(2);
    const erro = assets.find((a) => a.type === 'url' && (a.data as { port?: number }).port === 443);
    expect(erro?.data).toMatchObject({ error: 'DEPTH_ZERO_SELF_SIGNED_CERT' }); // TLS nunca é desligado

    const findings = await prisma.finding.findMany({
      where: { scanId: id },
      orderBy: { dedupKey: 'asc' },
    });
    expect(findings.map((f) => f.dedupKey)).toEqual([
      `recon.exposed-service:${IP}:6379`,
      `recon.http-cleartext:${IP}:80`,
      `recon.server-banner:svc:${IP}:80`,
      `recon.tls-expired:${IP}:443`,
      `recon.tls-hostname-mismatch:${IP}:443`,
    ]);
    for (const f of findings) {
      expect(f.checkId.startsWith('recon.')).toBe(true);
      expect(['info', 'low']).toContain(f.severity);
      expect(f.reproduction.length).toBeGreaterThan(0);
    }
    // a API filtra por módulo pelo prefixo do checkId
    expect(findings.filter((f) => f.checkId.startsWith('recon.'))).toHaveLength(5);
  });

  it('10. reprocessar (job reentregue) não duplica asset nem finding', async () => {
    const id = await novoScan('standard');
    const { processor } = setup();
    expect(await processor.process(id)).toBe('done');
    const antes = {
      assets: await prisma.asset.count({ where: { scanId: id } }),
      findings: await prisma.finding.count({ where: { scanId: id } }),
    };
    expect(antes).toEqual({ assets: 8, findings: 5 });

    await prisma.scan.update({ where: { id }, data: { status: 'running' } }); // worker caiu e o job voltou
    expect(await processor.process(id, { resume: true })).toBe('done');
    expect({
      assets: await prisma.asset.count({ where: { scanId: id } }),
      findings: await prisma.finding.count({ where: { scanId: id } }),
    }).toEqual(antes);
    expect((await prisma.task.findFirstOrThrow({ where: { scanId: id } })).attempts).toBe(2);
  });

  it('5. perfil passive num alvo host: nenhum check ativo roda, nmap e HTTP ficam intocados', async () => {
    const id = await novoScan('passive');
    const { processor, nmap, http } = setup();
    expect(await processor.process(id)).toBe('done');
    expect(nmap.calls).toHaveLength(0);
    expect(http.requests).toHaveLength(0);
    expect(await prisma.asset.count({ where: { scanId: id } })).toBe(0);
    expect(await prisma.finding.count({ where: { scanId: id } })).toBe(0);
  });

  it('o perfil deep chega ao nmap como deep', async () => {
    const id = await novoScan('deep');
    const { processor, nmap } = setup();
    expect(await processor.process(id)).toBe('done');
    expect(nmap.calls[0]?.profile).toBe('deep');
  });

  it('alvo URL: só o probe HTTP (GET e HEAD) roda e não há port scan', async () => {
    const id = await novoScan('standard', 'url');
    const { processor, nmap, http } = setup();
    expect(await processor.process(id)).toBe('done');
    expect(nmap.calls).toHaveLength(0);
    expect(http.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      `GET http://${IP}/`,
      `HEAD http://${IP}/`,
    ]);
    const assets = await prisma.asset.findMany({ where: { scanId: id } });
    expect(assets.map((a) => a.type)).toEqual(['url']);
  });
});
