import { describe, expect, it } from 'vitest';
import { ScopeResolver } from './resolver';
import type { LabContext } from './types';
import { FakeDns, NOW, daysAgo, programCtx } from './testing';

const LAB: LabContext = { mode: 'lab', allowlist: ['10.129.0.0/16'] };

function resolverWith(table: ConstructorParameters<typeof FakeDns>[0], extra: string[] = []) {
  return new ScopeResolver({ dns: new FakeDns(table), extraBlockedCidrs: extra, now: () => NOW });
}

describe('regressão de escopo (spec fase 1)', () => {
  it('1. destino em CIDR da allowlist de lab: allow', async () => {
    const d = await resolverWith({}).resolve('10.129.0.10', LAB);
    expect(d.allowed).toBe(true);
    expect(d.rule).toEqual({ kind: 'cidr', value: '10.129.0.0/16' });
  });

  it('1b. host do lab que resolve para a allowlist: allow', async () => {
    const r = resolverWith({ 'box.htb': { addresses: ['10.129.0.10'], cnames: [] } });
    expect((await r.resolve('http://box.htb:8080/login', LAB)).allowed).toBe(true);
  });

  it('2. destino fora da allowlist (IP público): block', async () => {
    const d = await resolverWith({}).resolve('93.184.216.34', LAB);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/fora da allowlist/);
  });

  it('3. host que resolve para a LAN: block, mesmo se a allowlist ou o escopo o listarem', async () => {
    const r = resolverWith({
      'nas.exemplo.com': { addresses: ['192.168.1.50'], cnames: [] },
      'box.htb': { addresses: ['192.168.1.50'], cnames: [] },
    });
    const lab = await r.resolve('box.htb', { mode: 'lab', allowlist: ['192.168.0.0/16'] });
    expect(lab.allowed).toBe(false);
    expect(lab.reason).toMatch(/bloqueio absoluto/);

    const prog = await r.resolve(
      'nas.exemplo.com',
      programCtx({
        inScope: [
          { kind: 'host', value: 'nas.exemplo.com' },
          { kind: 'cidr', value: '192.168.0.0/16' },
        ],
      }),
    );
    expect(prog.allowed).toBe(false);
    expect(prog.reason).toMatch(/bloqueio absoluto/);
  });

  it('3b. LAN extra configurada em FYLAX_LAN_CIDRS é bloqueio absoluto', async () => {
    const r = resolverWith({}, ['10.50.0.0/24']);
    const d = await r.resolve('10.50.0.7', { mode: 'lab', allowlist: ['10.0.0.0/8'] });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/LAN configurada/);
  });

  it('4. metadados de cloud (169.254.169.254): block sempre', async () => {
    const r = resolverWith({ 'meta.exemplo.com': { addresses: ['169.254.169.254'], cnames: [] } });
    for (const ctx of [
      { mode: 'lab', allowlist: ['169.254.0.0/16'] } as LabContext,
      programCtx({ inScope: [{ kind: 'cidr', value: '169.254.0.0/16' }] }),
      programCtx({ inScope: [{ kind: 'host', value: 'meta.exemplo.com' }] }),
    ]) {
      expect((await r.resolve('169.254.169.254', ctx)).allowed).toBe(false);
      expect((await r.resolve('http://169.254.169.254/latest/meta-data/', ctx)).allowed).toBe(
        false,
      );
      expect((await r.resolve('meta.exemplo.com', ctx)).allowed).toBe(false);
    }
  });

  it('5. programa: host em inScope wildcard allow; o mesmo em outOfScope block', async () => {
    const r = resolverWith({ 'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } });
    const ctx = programCtx({});
    const ok = await r.resolve('https://api.exemplo.com/v1', ctx);
    expect(ok.allowed).toBe(true);
    expect(ok.rule).toEqual({ kind: 'wildcard', value: '*.exemplo.com' });
    expect(ok.maxRequestsPerSecond).toBe(5);

    const out = await r.resolve(
      'https://api.exemplo.com/v1',
      programCtx({ outOfScope: [{ kind: 'host', value: 'api.exemplo.com' }] }),
    );
    expect(out.allowed).toBe(false);
    expect(out.reason).toMatch(/outOfScope/);
  });

  it('6. host de terceiro via CNAME de subdomínio in-scope: block', async () => {
    const r = resolverWith({
      'cdn.exemplo.com': { addresses: ['151.101.1.1'], cnames: ['exemplo.fastly.net'] },
      'www.exemplo.com': { addresses: ['93.184.216.34'], cnames: ['lb.exemplo.com'] },
    });
    const bloqueado = await r.resolve('https://cdn.exemplo.com', programCtx({}));
    expect(bloqueado.allowed).toBe(false);
    expect(bloqueado.reason).toMatch(/CNAME para host de terceiro.*exemplo\.fastly\.net/);

    // CNAME que continua dentro do escopo passa.
    expect((await r.resolve('https://www.exemplo.com', programCtx({}))).allowed).toBe(true);

    // Terceiro listado explicitamente passa.
    const listado = programCtx({
      inScope: [
        { kind: 'wildcard', value: '*.exemplo.com' },
        { kind: 'host', value: 'exemplo.fastly.net' },
      ],
    });
    expect((await r.resolve('https://cdn.exemplo.com', listado)).allowed).toBe(true);
  });

  it('7. automation forbidden: request ativo block, recon passivo allow', async () => {
    const r = resolverWith({ 'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } });
    const ctx = programCtx({ rules: { automation: 'forbidden' } });
    const ativo = await r.resolve('https://api.exemplo.com', ctx);
    expect(ativo.allowed).toBe(false);
    expect(ativo.reason).toMatch(/proíbe automação/);
    expect((await r.resolve('https://api.exemplo.com', ctx, { passive: true })).allowed).toBe(true);
  });

  it('7b. recon passivo não escapa de outOfScope nem de inScope', async () => {
    const r = resolverWith({ 'x.outro.com': { addresses: ['93.184.216.34'], cnames: [] } });
    const ctx = programCtx({ rules: { automation: 'forbidden' } });
    expect((await r.resolve('https://x.outro.com', ctx, { passive: true })).allowed).toBe(false);
  });

  it('8. reviewedAt com 40 dias e reviewMaxAgeDays 30: block', async () => {
    const r = resolverWith({ 'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } });
    const d = await r.resolve(
      'https://api.exemplo.com',
      programCtx({ reviewedAt: daysAgo(40), rules: { reviewMaxAgeDays: 30 } }),
    );
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/brief precisa de nova revisão/);
  });

  it('8b. reviewMaxAgeDays padrão é 30 e o limite exato ainda passa', async () => {
    const r = resolverWith({ 'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } });
    expect(
      (await r.resolve('https://api.exemplo.com', programCtx({ reviewedAt: daysAgo(31) }))).allowed,
    ).toBe(false);
    expect(
      (await r.resolve('https://api.exemplo.com', programCtx({ reviewedAt: daysAgo(30) }))).allowed,
    ).toBe(true);
    const longo = programCtx({ reviewedAt: daysAgo(40), rules: { reviewMaxAgeDays: 60 } });
    expect((await r.resolve('https://api.exemplo.com', longo)).allowed).toBe(true);
  });
});

describe('bordas do ScopeResolver', () => {
  const pub = { addresses: ['93.184.216.34'], cnames: [] };

  it('falha de DNS: block (não arrisca)', async () => {
    const d = await resolverWith({}).resolve('https://sumiu.exemplo.com', programCtx({}));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/falha ao resolver DNS/);
  });

  it('DNS sem endereços: block', async () => {
    const r = resolverWith({ 'a.exemplo.com': { addresses: [], cnames: [] } });
    expect((await r.resolve('https://a.exemplo.com', programCtx({}))).allowed).toBe(false);
  });

  it('um IP ruim entre vários resolvidos bloqueia tudo', async () => {
    const r = resolverWith({
      'a.exemplo.com': { addresses: ['93.184.216.34', '127.0.0.1'], cnames: [] },
    });
    expect((await r.resolve('https://a.exemplo.com', programCtx({}))).allowed).toBe(false);
  });

  it('loopback, IPv6 e IPv4 embutido em IPv6 são bloqueados', async () => {
    const r = resolverWith({});
    for (const alvo of [
      '127.0.0.1',
      'http://localhost.invalid@127.0.0.1/',
      '[::1]',
      'http://[::1]:8080/',
      'http://[::ffff:127.0.0.1]/',
      'http://[::ffff:a9fe:a9fe]/',
      'http://[fe80::1]/',
      'http://[fd00:ec2::254]/',
      'http://2130706433/',
      'http://0x7f.1/',
      '0.0.0.0',
    ]) {
      expect((await r.resolve(alvo, LAB)).allowed, alvo).toBe(false);
    }
  });

  it('esquema não http(s) e credenciais embutidas: block', async () => {
    const r = resolverWith({ 'a.exemplo.com': pub });
    for (const alvo of [
      'file:///etc/passwd',
      'ftp://a.exemplo.com',
      'gopher://a.exemplo.com',
      '',
    ]) {
      expect((await r.resolve(alvo, programCtx({}))).allowed, alvo).toBe(false);
    }
    const cred = await r.resolve('https://a.exemplo.com@evil.exemplo.org/', programCtx({}));
    expect(cred.allowed).toBe(false);
    const cred2 = await r.resolve('https://user:pw@a.exemplo.com/', programCtx({}));
    expect(cred2.reason).toMatch(/credenciais/);
  });

  it('wildcard: não casa o apex nem sufixo parecido; casa profundidade maior', async () => {
    const r = resolverWith({
      'exemplo.com': pub,
      'evil-exemplo.com': pub,
      'a.b.exemplo.com': pub,
      'exemplo.com.evil.org': pub,
    });
    const ctx = programCtx({});
    expect((await r.resolve('https://exemplo.com', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://evil-exemplo.com', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://exemplo.com.evil.org', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://a.b.exemplo.com', ctx)).allowed).toBe(true);
  });

  it('host é case-insensitive e ignora ponto final', async () => {
    const r = resolverWith({ 'api.exemplo.com': pub });
    const ctx = programCtx({ inScope: [{ kind: 'host', value: 'API.Exemplo.com' }] });
    expect((await r.resolve('https://api.exemplo.com./x', ctx)).allowed).toBe(true);
  });

  it('portas: entrada com ports só libera as listadas; porta padrão do esquema conta', async () => {
    const r = resolverWith({ 'api.exemplo.com': pub });
    const ctx = programCtx({
      inScope: [{ kind: 'host', value: 'api.exemplo.com', ports: [443, 8443] }],
    });
    expect((await r.resolve('https://api.exemplo.com', ctx)).allowed).toBe(true);
    expect((await r.resolve('https://api.exemplo.com:8443', ctx)).allowed).toBe(true);
    expect((await r.resolve('http://api.exemplo.com', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://api.exemplo.com:9000', ctx)).allowed).toBe(false);
    // destino sem esquema e sem porta não prova a porta: block
    expect((await r.resolve('api.exemplo.com', ctx)).allowed).toBe(false);
  });

  it('outOfScope com porta só exclui aquela porta', async () => {
    const r = resolverWith({ 'api.exemplo.com': pub });
    const ctx = programCtx({
      outOfScope: [{ kind: 'host', value: 'api.exemplo.com', ports: [8080] }],
    });
    expect((await r.resolve('https://api.exemplo.com', ctx)).allowed).toBe(true);
    expect((await r.resolve('http://api.exemplo.com:8080', ctx)).allowed).toBe(false);
  });

  it('urlPrefix respeita o limite de caminho e normaliza traversal', async () => {
    const r = resolverWith({ 'ex.com': pub });
    const ctx = programCtx({ inScope: [{ kind: 'urlPrefix', value: 'https://ex.com/api/*' }] });
    expect((await r.resolve('https://ex.com/api/users?id=1', ctx)).allowed).toBe(true);
    expect((await r.resolve('https://ex.com/api', ctx)).allowed).toBe(true);
    expect((await r.resolve('https://ex.com/apix', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://ex.com/other', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://ex.com/api/../admin', ctx)).allowed).toBe(false);
    expect((await r.resolve('https://ex.com/api/%2e%2e/admin', ctx)).allowed).toBe(false);
    expect((await r.resolve('http://ex.com/api/users', ctx)).allowed).toBe(false);
    expect((await r.resolve('ex.com', ctx)).allowed).toBe(false);
  });

  it('urlPrefix em outOfScope exclui só o caminho, não o host inteiro', async () => {
    const r = resolverWith({ 'ex.com': pub });
    const ctx = programCtx({
      inScope: [{ kind: 'host', value: 'ex.com' }],
      outOfScope: [{ kind: 'urlPrefix', value: 'https://ex.com/admin/*' }],
    });
    expect((await r.resolve('https://ex.com/', ctx)).allowed).toBe(true);
    expect((await r.resolve('https://ex.com/admin/users', ctx)).allowed).toBe(false);
  });

  it('cidr em inScope exige todos os IPs dentro; em outOfScope basta um', async () => {
    const r = resolverWith({
      'multi.exemplo.com': { addresses: ['203.0.113.5', '198.51.100.9'], cnames: [] },
    });
    const parcial = programCtx({ inScope: [{ kind: 'cidr', value: '203.0.113.0/24' }] });
    expect((await r.resolve('https://multi.exemplo.com', parcial)).allowed).toBe(false);
    const total = programCtx({
      inScope: [
        { kind: 'cidr', value: '203.0.113.0/24' },
        { kind: 'cidr', value: '198.51.100.0/24' },
      ],
    });
    // cada entrada isolada não cobre todos os IPs
    expect((await r.resolve('https://multi.exemplo.com', total)).allowed).toBe(false);

    const unico = resolverWith({ 'um.exemplo.com': { addresses: ['203.0.113.5'], cnames: [] } });
    expect((await unico.resolve('https://um.exemplo.com', parcial)).allowed).toBe(true);
    const excl = programCtx({
      inScope: [{ kind: 'host', value: 'multi.exemplo.com' }],
      outOfScope: [{ kind: 'cidr', value: '198.51.100.0/24' }],
    });
    expect((await r.resolve('https://multi.exemplo.com', excl)).allowed).toBe(false);
  });

  it('automation unspecified: allow com taxa baixa e confirmação humana', async () => {
    const r = resolverWith({ 'api.exemplo.com': pub });
    const d = await r.resolve(
      'https://api.exemplo.com',
      programCtx({ rules: { automation: 'unspecified', maxRequestsPerSecond: 10 } }),
    );
    expect(d.allowed).toBe(true);
    expect(d.requiresConfirmation).toBe(true);
    expect(d.maxRequestsPerSecond).toBe(1);

    const menor = await r.resolve(
      'https://api.exemplo.com',
      programCtx({ rules: { automation: 'unspecified', maxRequestsPerSecond: 0.5 } }),
    );
    expect(menor.maxRequestsPerSecond).toBe(0.5);
  });

  it('default é block: host fora do inScope', async () => {
    const r = resolverWith({ 'outro.org': pub });
    const d = await r.resolve('https://outro.org', programCtx({}));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/default: block/);
  });

  it('entrada de escopo inválida nunca casa (fail closed)', async () => {
    const r = resolverWith({ 'api.exemplo.com': pub });
    const ctx = programCtx({
      inScope: [
        { kind: 'cidr', value: 'lixo' },
        { kind: 'urlPrefix', value: '::::' },
      ],
    });
    expect((await r.resolve('https://api.exemplo.com', ctx)).allowed).toBe(false);
  });
});
