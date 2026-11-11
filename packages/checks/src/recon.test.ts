import { describe, expect, it } from 'vitest';
import type { Check, NmapResult, TargetRef } from '@fylax/core';
import { certificateCoversHost, createReconChecks, nmapProfileFor } from './index';
import { FakeHttp, FakeNmap, response, runScenario, transportError } from './testing';

const NOW = new Date('2026-11-11T12:00:00Z');
const checks = (): Check[] => createReconChecks({ now: () => NOW });

const HOST: TargetRef = { kind: 'host', value: '10.250.0.10', platform: 'local' };
const URL_TARGET: TargetRef = { kind: 'url', value: 'https://api.exemplo.com/', platform: 'htb' };

const certOk = {
  subject: 'commonName=api.exemplo.com',
  issuer: 'commonName=CA',
  san: ['api.exemplo.com'],
  notBefore: '2026-01-01T00:00:00',
  notAfter: '2027-01-01T00:00:00',
};

/** Uma máquina parecida com as fixtures do lab local. */
const LAB: NmapResult = {
  durationMs: 10,
  hosts: [
    {
      ip: '10.250.0.10',
      ports: [
        {
          port: 22,
          protocol: 'tcp',
          state: 'open',
          reason: 'syn-ack',
          service: {
            name: 'ssh',
            product: 'OpenSSH',
            version: '9.7',
            cpe: [],
            banner: 'SSH-2.0-OpenSSH_9.7',
          },
        },
        {
          port: 80,
          protocol: 'tcp',
          state: 'open',
          reason: 'syn-ack',
          service: {
            name: 'http',
            product: 'nginx',
            version: '1.27.2',
            cpe: ['cpe:/a:igor_sysoev:nginx:1.27.2'],
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
            notBefore: '2026-11-08T10:00:00',
            notAfter: '2026-11-16T10:00:00',
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

const labHttp = () =>
  new FakeHttp((req) => {
    if (req.url === 'http://10.250.0.10/') {
      return response({
        headers: { server: 'nginx/1.27.2', 'content-type': 'text/html' },
        body: '<html><title> Fylax  Lab\n Web </title></html>',
      });
    }
    return transportError('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

describe('recon: host alvo (cenário do lab)', () => {
  it('descobre portas e serviços, e gera os findings esperados', async () => {
    const http = labHttp();
    const nmap = new FakeNmap(LAB);
    const { assets, findings, ran } = await runScenario({
      checks: checks(),
      target: HOST,
      http,
      nmap,
    });

    expect(ran).toEqual([
      'recon.port-scan',
      'recon.http-discover',
      'recon.tls-info',
      'recon.server-banner',
      'recon.exposed-service',
    ]);
    expect(nmap.calls).toEqual([{ host: '10.250.0.10', profile: 'standard' }]);

    expect(assets.filter((a) => a.type === 'port').map((a) => a.data.port)).toEqual([
      22, 80, 443, 6379,
    ]);
    const svc = assets.filter((a) => a.type === 'service' && a.data.port !== undefined);
    expect(svc.map((a) => a.data.port)).toEqual([22, 80, 443, 6379]);
    expect(svc.find((a) => a.data.port === 80)?.data).toMatchObject({
      product: 'nginx',
      version: '1.27.2',
      host: '10.250.0.10',
      ip: '10.250.0.10',
    });
    expect(svc.find((a) => a.data.port === 443)?.data.tls).toMatchObject({
      san: ['fixture.invalid'],
    });

    // http-discover: porta 80 responde; 443 tem certificado autoassinado e vira asset com erro (TLS nunca é desligado)
    const urls = assets.filter((a) => a.type === 'url');
    expect(urls.find((u) => u.data.port === 80)?.data).toMatchObject({
      url: 'http://10.250.0.10/',
      via: 'http-discover',
      status: 200,
      title: 'Fylax Lab Web',
      server: 'nginx/1.27.2',
    });
    expect(urls.find((u) => u.data.port === 443)?.data).toEqual({
      url: 'https://10.250.0.10/',
      via: 'http-discover',
      port: 443,
      error: 'DEPTH_ZERO_SELF_SIGNED_CERT',
    });
    expect(http.requests.map((r) => r.url)).toEqual([
      'http://10.250.0.10/',
      'https://10.250.0.10/',
    ]);

    const ids = findings.map((f) => f.dedupKey).sort();
    expect(ids).toEqual([
      'recon.exposed-service:10.250.0.10:6379',
      'recon.http-cleartext:10.250.0.10:80',
      'recon.server-banner:svc:10.250.0.10:22',
      'recon.server-banner:svc:10.250.0.10:80',
      'recon.tls-expired:10.250.0.10:443',
      'recon.tls-hostname-mismatch:10.250.0.10:443',
    ]);
    // ssh aberto não é "serviço sensível" e o cabeçalho Server não duplica o finding do nmap na porta 80
    expect(
      findings.some((f) => f.dedupKey.startsWith('recon.exposed-service:10.250.0.10:22')),
    ).toBe(false);
    expect(findings.some((f) => f.dedupKey.startsWith('recon.server-banner:http'))).toBe(false);
  });

  it('todo finding segue as convenções: checkId do módulo, dedupKey único, severidade baixa, com reprodução', async () => {
    const { findings } = await runScenario({
      checks: checks(),
      target: HOST,
      http: labHttp(),
      nmap: new FakeNmap(LAB),
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(new Set(findings.map((f) => f.dedupKey)).size).toBe(findings.length);
    for (const f of findings) {
      expect(f.checkId.startsWith('recon.'), f.checkId).toBe(true);
      expect(['info', 'low']).toContain(f.severity);
      expect(f.reproduction.length).toBeGreaterThan(0);
      expect(f.asset).toMatch(/^10\.250\.0\.10:\d+$/);
      expect(f.title).toBeTruthy();
      expect(f.description).toBeTruthy();
    }
  });

  it('rodar duas vezes gera os mesmos assets e findings (determinístico, sem timestamps)', async () => {
    const a = await runScenario({
      checks: checks(),
      target: HOST,
      http: labHttp(),
      nmap: new FakeNmap(LAB),
    });
    const b = await runScenario({
      checks: checks(),
      target: HOST,
      http: labHttp(),
      nmap: new FakeNmap(LAB),
    });
    expect(JSON.stringify(a.assets)).toBe(JSON.stringify(b.assets));
    expect(a.findings.map((f) => f.dedupKey)).toEqual(b.findings.map((f) => f.dedupKey));
  });

  it('sem portas abertas: sem assets de serviço e sem findings', async () => {
    const { assets, findings } = await runScenario({
      checks: checks(),
      target: HOST,
      nmap: new FakeNmap({ hosts: [{ ip: '10.250.0.10', ports: [] }], durationMs: 1 }),
    });
    expect(assets.filter((a) => a.type === 'port')).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('erro do nmap (inclusive violação de escopo) sobe: quem registra é o runner', async () => {
    const quebrado = new FakeNmap(new Error('fora de escopo'));
    await expect(runScenario({ checks: checks(), target: HOST, nmap: quebrado })).rejects.toThrow(
      'fora de escopo',
    );
  });
});

describe('recon: perfis', () => {
  it('o perfil deep usa o nmap deep; os demais usam standard', async () => {
    expect(nmapProfileFor('deep')).toBe('deep');
    for (const p of ['standard', 'bounty', 'passive']) expect(nmapProfileFor(p)).toBe('standard');
    const nmap = new FakeNmap();
    await runScenario({ checks: checks(), target: HOST, profile: 'deep', nmap });
    expect(nmap.calls[0]?.profile).toBe('deep');
  });

  it('5. perfil passivo: nenhum check ativo roda, o nmap não é chamado e não há request em host sem URL', async () => {
    const nmap = new FakeNmap(LAB);
    const http = labHttp();
    const { ran } = await runScenario({
      checks: checks(),
      target: HOST,
      profile: 'passive',
      onlyPassive: true,
      nmap,
      http,
    });
    expect(nmap.calls).toHaveLength(0);
    expect(http.requests).toHaveLength(0);
    expect(ran).not.toContain('recon.port-scan');
    expect(ran).not.toContain('recon.http-discover');
  });

  it('alvo URL: só o probe HTTP roda; não há port scan do host', async () => {
    const nmap = new FakeNmap(LAB);
    const { ran } = await runScenario({
      checks: checks(),
      target: URL_TARGET,
      nmap,
      http: new FakeHttp(() => response()),
    });
    expect(ran).toContain('recon.http-probe');
    expect(ran).not.toContain('recon.port-scan');
    expect(nmap.calls).toHaveLength(0);
  });

  it('os checks que só analisam assets são passivos; os que geram tráfego não são', () => {
    const porId = Object.fromEntries(checks().map((c) => [c.id, c.passive === true]));
    expect(porId).toEqual({
      'recon.http-probe': true, // request passivo (GET e HEAD em URL conhecida)
      'recon.port-scan': false,
      'recon.http-discover': false,
      'recon.tls-info': true,
      'recon.server-banner': true,
      'recon.exposed-service': true,
    });
  });
});

describe('recon.http-probe', () => {
  it('faz GET e HEAD e guarda status, título, servidor e o status do HEAD (nunca o corpo)', async () => {
    const http = new FakeHttp((req) =>
      req.method === 'HEAD'
        ? response({ status: 405 })
        : response({
            headers: { server: 'Apache/2.4.58', 'x-powered-by': 'PHP/8.3.1' },
            body: '<title>Início</title>segredo-no-corpo',
          }),
    );
    const { assets, findings } = await runScenario({ checks: checks(), target: URL_TARGET, http });
    expect(http.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET https://api.exemplo.com/',
      'HEAD https://api.exemplo.com/',
    ]);
    const url = assets.find((a) => a.type === 'url' && a.data.via === 'http-probe');
    expect(url?.data).toEqual({
      url: 'https://api.exemplo.com/',
      via: 'http-probe',
      status: 200,
      title: 'Início',
      server: 'Apache/2.4.58',
      poweredBy: 'PHP/8.3.1',
      headStatus: 405,
    });
    expect(JSON.stringify(assets)).not.toContain('segredo-no-corpo');
    // o cabeçalho Server com versão vira finding informativo
    expect(findings.map((f) => f.dedupKey).sort()).toEqual([
      'recon.server-banner:http:api.exemplo.com:443:poweredBy',
      'recon.server-banner:http:api.exemplo.com:443:server',
    ]);
  });

  it('falha de transporte (certificado não verificável) vira asset com erro, não falha do check', async () => {
    const { assets } = await runScenario({
      checks: checks(),
      target: URL_TARGET,
      http: new FakeHttp(() => transportError('UNABLE_TO_VERIFY_LEAF_SIGNATURE')),
    });
    expect(assets.find((a) => a.data.via === 'http-probe')?.data).toEqual({
      url: 'https://api.exemplo.com/',
      via: 'http-probe',
      error: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    });
  });

  it('violação de escopo e erros inesperados sobem', async () => {
    const escopo = new Error('fora de escopo');
    escopo.name = 'ScopeViolationError';
    await expect(
      runScenario({ checks: checks(), target: URL_TARGET, http: new FakeHttp(() => escopo) }),
    ).rejects.toThrow('fora de escopo');
    await expect(
      runScenario({
        checks: checks(),
        target: URL_TARGET,
        http: new FakeHttp(() => new Error('bug')),
      }),
    ).rejects.toThrow('bug');
  });
});

describe('recon.http-cleartext', () => {
  const nmapWith = (port: number, name: string, tunnel?: 'ssl') =>
    new FakeNmap({
      durationMs: 1,
      hosts: [
        {
          ip: '10.250.0.10',
          ports: [
            {
              port,
              protocol: 'tcp',
              state: 'open',
              reason: 'x',
              service: { name, cpe: [], ...(tunnel ? { tunnel } : {}) },
            },
          ],
        },
      ],
    });
  const cleartexts = async (nmap: FakeNmap, http: FakeHttp) =>
    (await runScenario({ checks: checks(), target: HOST, nmap, http })).findings.filter(
      (f) => f.checkId === 'recon.http-cleartext',
    );

  it('HTTP na porta padrão sem redirect: finding; com redirect para https: nada', async () => {
    expect(await cleartexts(nmapWith(80, 'http'), new FakeHttp(() => response()))).toHaveLength(1);
    expect(await cleartexts(nmapWith(8080, 'http'), new FakeHttp(() => response()))).toHaveLength(
      1,
    );
    const redir = new FakeHttp(() =>
      response({ status: 301, headers: { location: 'https://10.250.0.10/' } }),
    );
    expect(await cleartexts(nmapWith(80, 'http'), redir)).toHaveLength(0);
    // redirect para outro http continua sendo texto claro
    const redirHttp = new FakeHttp(() =>
      response({ status: 302, headers: { location: 'http://10.250.0.10/login' } }),
    );
    expect(await cleartexts(nmapWith(80, 'http'), redirHttp)).toHaveLength(1);
  });

  it('porta HTTP não padrão, HTTPS e falha de conexão não geram o finding', async () => {
    expect(await cleartexts(nmapWith(8123, 'http'), new FakeHttp(() => response()))).toHaveLength(
      0,
    );
    expect(
      await cleartexts(nmapWith(443, 'http', 'ssl'), new FakeHttp(() => response())),
    ).toHaveLength(0);
    expect(
      await cleartexts(nmapWith(80, 'http'), new FakeHttp(() => transportError('ECONNRESET'))),
    ).toHaveLength(0);
  });

  it('URL de portas não padrão inclui a porta; padrão não inclui', async () => {
    const http = new FakeHttp(() => response());
    await runScenario({ checks: checks(), target: HOST, nmap: nmapWith(8123, 'http'), http });
    await runScenario({
      checks: checks(),
      target: HOST,
      nmap: nmapWith(443, 'https', 'ssl'),
      http,
    });
    expect(http.requests.map((r) => r.url)).toEqual([
      'http://10.250.0.10:8123/',
      'https://10.250.0.10/',
    ]);
  });
});

describe('recon.tls-info', () => {
  const withTls = (tls: Record<string, unknown>) =>
    new FakeNmap({
      durationMs: 1,
      hosts: [
        {
          ip: '10.250.0.10',
          ports: [
            {
              port: 443,
              protocol: 'tcp',
              state: 'open',
              reason: 'x',
              service: { name: 'ssl', cpe: [] },
              tls: { ...certOk, ...tls } as never,
            },
          ],
        },
      ],
    });
  const run = async (tls: Record<string, unknown>, host = 'api.exemplo.com') =>
    (
      await runScenario({ checks: checks(), target: { ...HOST, value: host }, nmap: withTls(tls) })
    ).findings.filter((f) => f.checkId.startsWith('recon.tls-'));

  it('certificado vencido, perto de vencer e saudável', async () => {
    const vencido = await run({ notAfter: '2026-10-01T00:00:00' });
    expect(vencido.map((f) => f.checkId)).toEqual(['recon.tls-expired']);
    expect(vencido[0]?.title).toMatch(/vencido/);
    expect(vencido[0]?.evidence).toMatchObject({ expiredDaysAgo: 41 });

    const quaseVencendo = await run({ notAfter: '2026-11-20T12:00:00' });
    expect(quaseVencendo[0]?.title).toMatch(/expira em menos de 14 dias/);
    expect(quaseVencendo[0]?.evidence).toMatchObject({ daysLeft: 9 });

    expect(await run({ notAfter: '2026-12-30T00:00:00' })).toHaveLength(0);
    // limite: exatamente 14 dias ainda não alerta
    expect(await run({ notAfter: '2026-11-25T12:00:00' })).toHaveLength(0);
    expect((await run({ notAfter: '2026-11-25T11:59:59' })).map((f) => f.checkId)).toEqual([
      'recon.tls-expired',
    ]);
  });

  it('aceita datas com fuso e ignora data inválida', async () => {
    expect((await run({ notAfter: '2026-10-01T00:00:00Z' })).map((f) => f.checkId)).toEqual([
      'recon.tls-expired',
    ]);
    expect((await run({ notAfter: '2026-10-01T00:00:00+00:00' })).map((f) => f.checkId)).toEqual([
      'recon.tls-expired',
    ]);
    expect(await run({ notAfter: 'ontem' })).toHaveLength(0);
  });

  it('nome do certificado: SAN, curinga de um rótulo, IP e CN quando não há SAN', async () => {
    expect(await run({}, 'api.exemplo.com')).toHaveLength(0);
    expect((await run({}, 'outro.exemplo.com')).map((f) => f.checkId)).toEqual([
      'recon.tls-hostname-mismatch',
    ]);

    expect(await run({ san: ['*.exemplo.com'] }, 'a.exemplo.com')).toHaveLength(0);
    expect(
      (await run({ san: ['*.exemplo.com'] }, 'a.b.exemplo.com')).map((f) => f.checkId),
    ).toEqual(['recon.tls-hostname-mismatch']);
    expect((await run({ san: ['*.exemplo.com'] }, 'exemplo.com')).map((f) => f.checkId)).toEqual([
      'recon.tls-hostname-mismatch',
    ]);

    expect(await run({ san: ['10.250.0.10'] }, '10.250.0.10')).toHaveLength(0);
    expect((await run({ san: ['fixture.invalid'] }, '10.250.0.10')).map((f) => f.checkId)).toEqual([
      'recon.tls-hostname-mismatch',
    ]);

    expect(
      await run(
        { san: [], subject: 'organizationName=X/commonName=api.exemplo.com' },
        'api.exemplo.com',
      ),
    ).toHaveLength(0);
    expect(
      (await run({ san: [], subject: 'commonName=outro.com' }, 'api.exemplo.com')).map(
        (f) => f.checkId,
      ),
    ).toEqual(['recon.tls-hostname-mismatch']);
  });

  it('certificateCoversHost é insensível a maiúsculas', () => {
    expect(certificateCoversHost({ ...certOk, san: ['API.Exemplo.COM'] }, 'api.exemplo.com')).toBe(
      true,
    );
  });
});

describe('recon.exposed-service', () => {
  const portOnly = (port: number) =>
    new FakeNmap({
      durationMs: 1,
      hosts: [
        { ip: '10.250.0.10', ports: [{ port, protocol: 'tcp', state: 'open', reason: 'x' }] },
      ],
    });
  const exposed = async (nmap: FakeNmap) =>
    (await runScenario({ checks: checks(), target: HOST, nmap })).findings.filter(
      (f) => f.checkId === 'recon.exposed-service',
    );

  it('detecta pelo nome do serviço (confiança alta) e pela porta quando não há serviço (confiança média)', async () => {
    const porNome = await exposed(new FakeNmap(LAB));
    expect(porNome).toHaveLength(1);
    expect(porNome[0]).toMatchObject({
      asset: '10.250.0.10:6379',
      confidence: 'high',
      severity: 'info',
    });
    expect(porNome[0]?.description).toMatch(/banco de dados/);

    const porPorta = await exposed(portOnly(3306));
    expect(porPorta[0]).toMatchObject({ confidence: 'medium', asset: '10.250.0.10:3306' });
  });

  it('portas comuns e serviços inofensivos não geram finding', async () => {
    for (const port of [22, 80, 443, 8080])
      expect(await exposed(portOnly(port)), String(port)).toHaveLength(0);
  });

  it('não duplica quando há asset de porta e de serviço para a mesma porta', async () => {
    expect(await exposed(new FakeNmap(LAB))).toHaveLength(1);
  });
});
