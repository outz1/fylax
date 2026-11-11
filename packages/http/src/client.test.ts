import { describe, expect, it } from 'vitest';
import type { Asset, AssetSink } from '@fylax/core';
import { ScopeGuard, ScopeResolver, ScopeViolationError, type ScopeContext } from '@fylax/scope';
import { FakeDns, MemoryAudit, NOW, programCtx } from '@fylax/scope/testing';
import { PROFILE_MAX_RPS, ScopedHttpClient } from './client';
import {
  TransportError,
  type HttpTransport,
  type TransportRequest,
  type TransportResponse,
} from './transport';

const PUBLIC = { addresses: ['93.184.216.34'], cnames: [] };

class FakeTransport implements HttpTransport {
  readonly calls: TransportRequest[] = [];
  constructor(
    private readonly script: (req: TransportRequest, n: number) => TransportResponse | Error,
  ) {}

  async send(req: TransportRequest): Promise<TransportResponse> {
    this.calls.push(req);
    const r = this.script(req, this.calls.length);
    if (r instanceof Error) throw r;
    return r;
  }
}

const ok = (
  body = 'ok',
  headers: Record<string, string> = {},
  status = 200,
): TransportResponse => ({
  status,
  headers,
  body,
  bytes: body.length,
  truncated: false,
});
const redirect = (location: string, status = 302) => ok('', { location }, status);

class MemoryAssets implements AssetSink {
  readonly items: Asset[] = [];
  async record(a: Asset): Promise<void> {
    this.items.push(a);
  }
}

function setup(opts: {
  transport: HttpTransport;
  context?: ScopeContext;
  dns?: Record<string, { addresses: string[]; cnames: string[] }>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  retries?: number;
  maxRedirects?: number;
}) {
  const audit = new MemoryAudit();
  const assets = new MemoryAssets();
  const dns = new FakeDns(
    opts.dns ?? {
      'api.exemplo.com': PUBLIC,
      'www.exemplo.com': PUBLIC,
      'outro.org': PUBLIC,
    },
  );
  const guard = new ScopeGuard(new ScopeResolver({ dns, now: () => NOW }), audit);
  const client = new ScopedHttpClient({
    guard,
    context: opts.context ?? programCtx({ rules: { maxRequestsPerSecond: 100 } }),
    profile: 'standard',
    audit,
    assets,
    scanId: 'scan-1',
    transport: opts.transport,
    sleep: opts.sleep ?? (async () => {}),
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.retries !== undefined ? { retries: opts.retries } : {}),
    ...(opts.maxRedirects !== undefined ? { maxRedirects: opts.maxRedirects } : {}),
  });
  return { client, audit, assets };
}

describe('ScopedHttpClient: escopo', () => {
  it('bloqueado: lança ScopeViolationError, não toca a rede e audita só scope.block', async () => {
    const transport = new FakeTransport(() => ok());
    const { client, audit } = setup({ transport });

    await expect(
      client.request({ method: 'GET', url: 'https://outro.org/' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(
      client.request({ method: 'GET', url: 'http://127.0.0.1:8080/' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    await expect(
      client.request({ method: 'GET', url: 'http://169.254.169.254/latest/meta-data/' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);

    expect(transport.calls).toHaveLength(0);
    expect(audit.actions()).toEqual(['scope.block', 'scope.block', 'scope.block']);
  });

  it('permitido: fixa o IP validado, audita scope.allow e http.request e não vaza a query', async () => {
    const transport = new FakeTransport(() => ok('corpo-secreto'));
    const { client, audit } = setup({ transport });

    const res = await client.request({
      method: 'GET',
      url: 'https://api.exemplo.com/v1?token=segredo123',
      headers: { Authorization: 'Bearer abc' },
    });

    expect(res.status).toBe(200);
    expect(transport.calls[0]?.pinnedIp).toBe('93.184.216.34');
    expect(audit.actions()).toEqual(['scope.allow', 'http.request']);
    const req = audit.entries[1];
    expect(req?.scanId).toBe('scan-1');
    expect(req?.detail).toMatchObject({
      method: 'GET',
      url: 'https://api.exemplo.com/v1?token=…',
      status: 200,
      bytes: 13,
      attempt: 0,
      hop: 0,
      decision: { allowed: true },
    });
    const log = JSON.stringify(audit.entries);
    for (const segredo of ['segredo123', 'Bearer abc', 'corpo-secreto']) {
      expect(log).not.toContain(segredo);
    }
  });

  it('revalida o DNS a cada request: se passar a resolver para a LAN, bloqueia (rebinding)', async () => {
    const dns = { 'api.exemplo.com': { ...PUBLIC } };
    const transport = new FakeTransport(() => ok());
    const { client } = setup({ transport, dns });

    await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
    dns['api.exemplo.com'] = { addresses: ['192.168.1.50'], cnames: [] };
    await expect(
      client.request({ method: 'GET', url: 'https://api.exemplo.com/' }),
    ).rejects.toBeInstanceOf(ScopeViolationError);
    expect(transport.calls).toHaveLength(1);
  });

  it('aplica requiredHeaders do programa, que prevalecem sobre os do check', async () => {
    const transport = new FakeTransport(() => ok());
    const { client } = setup({
      transport,
      context: programCtx({
        rules: { maxRequestsPerSecond: 100, requiredHeaders: { 'X-Research': 'edu' } },
      }),
    });
    await client.request({
      method: 'GET',
      url: 'https://api.exemplo.com/',
      headers: { 'x-research': 'forjado', Accept: 'application/json' },
    });
    expect(transport.calls[0]?.headers).toMatchObject({
      'x-research': 'edu',
      accept: 'application/json',
      'user-agent': 'fylax-vulnscan',
    });
  });

  it('não passa corpo de resposta cortado como completo: sinaliza truncated', async () => {
    const transport = new FakeTransport(() => ({ ...ok('abc'), truncated: true }));
    const { client } = setup({ transport });
    const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
    expect(res.truncated).toBe(true);
  });
});

describe('ScopedHttpClient: redirects', () => {
  it('9. redirect in-scope para destino out-of-scope: não seguido, registrado como asset', async () => {
    const transport = new FakeTransport(() => redirect('https://outro.org/painel?sid=abc'));
    const { client, audit, assets } = setup({ transport });

    const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/login' });

    expect(res.status).toBe(302);
    expect(res.redirect).toMatchObject({
      followed: false,
      location: 'https://outro.org/painel?sid=abc',
    });
    expect(res.redirect?.reason).toMatch(/redirect bloqueado/);
    expect(transport.calls).toHaveLength(1);
    expect(assets.items).toEqual([
      {
        type: 'url',
        data: expect.objectContaining({
          url: 'https://outro.org/painel?sid=…',
          from: 'https://api.exemplo.com/login',
          discoveredVia: 'redirect',
          blocked: true,
          followed: false,
        }),
      },
    ]);
    expect(audit.actions()).toEqual(['scope.allow', 'http.request', 'scope.block']);
    expect(JSON.stringify(assets.items)).not.toContain('sid=abc');
  });

  it('redirect para destino em escopo é revalidado e seguido; credenciais caem ao trocar de origem', async () => {
    const transport = new FakeTransport((_req, n) =>
      n === 1 ? redirect('https://www.exemplo.com/home') : ok('home'),
    );
    const { client, audit } = setup({ transport });

    const res = await client.request({
      method: 'GET',
      url: 'https://api.exemplo.com/',
      headers: { Authorization: 'Bearer abc', Cookie: 's=1', Accept: '*/*' },
    });

    expect(res.body).toBe('home');
    expect(transport.calls.map((c) => c.url)).toEqual([
      'https://api.exemplo.com/',
      'https://www.exemplo.com/home',
    ]);
    expect(transport.calls[0]?.headers['authorization']).toBe('Bearer abc');
    expect(transport.calls[1]?.headers['authorization']).toBeUndefined();
    expect(transport.calls[1]?.headers['cookie']).toBeUndefined();
    expect(transport.calls[1]?.headers['accept']).toBe('*/*');
    expect(audit.actions()).toEqual(['scope.allow', 'http.request', 'scope.allow', 'http.request']);
    expect(audit.entries[3]?.detail).toMatchObject({ hop: 1 });
  });

  it('limite de redirects: para e registra', async () => {
    const transport = new FakeTransport((req) => redirect(`${req.url}x`));
    const { client, assets } = setup({
      transport,
      maxRedirects: 2,
      dns: { 'api.exemplo.com': PUBLIC },
    });
    const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/a' });
    expect(transport.calls).toHaveLength(3);
    expect(res.redirect?.reason).toMatch(/limite de 2 redirects/);
    expect(assets.items).toHaveLength(1);
  });

  it('redirect de POST não é seguido', async () => {
    const transport = new FakeTransport(() => redirect('https://api.exemplo.com/ok', 307));
    const { client, assets } = setup({ transport });
    const res = await client.request({
      method: 'POST',
      url: 'https://api.exemplo.com/x',
      body: '{}',
    });
    expect(transport.calls).toHaveLength(1);
    expect(res.redirect?.reason).toMatch(/POST/);
    expect(assets.items).toHaveLength(1);
  });

  it('Location inválido devolve a resposta sem seguir', async () => {
    const transport = new FakeTransport(() => redirect('http://['));
    const { client } = setup({ transport });
    const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
    expect(res.redirect?.reason).toBe('Location inválido');
  });

  it('redirect para esquema perigoso ou metadados é bloqueado', async () => {
    for (const destino of [
      'file:///etc/passwd',
      'http://169.254.169.254/latest/',
      'http://127.0.0.1/',
    ]) {
      const transport = new FakeTransport(() => redirect(destino));
      const { client } = setup({ transport });
      const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
      expect(transport.calls, destino).toHaveLength(1);
      expect(res.redirect?.followed).toBe(false);
    }
  });
});

describe('ScopedHttpClient: rate limit e retry', () => {
  it('rate limit por host: respeita o teto do escopo (1 req/s)', async () => {
    let t = 0;
    const sleeps: number[] = [];
    const transport = new FakeTransport(() => ok());
    const { client } = setup({
      transport,
      now: () => t,
      sleep: async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
      context: programCtx({ rules: { automation: 'unspecified', maxRequestsPerSecond: 10 } }),
    });

    for (let i = 0; i < 3; i++)
      await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });

    expect(sleeps).toEqual([1000, 1000]); // 1ª passa de imediato; 2ª e 3ª esperam 1s
    expect(t).toBe(2000);
  });

  it('teto do perfil vale mesmo que o programa permita mais', async () => {
    let t = 0;
    const sleeps: number[] = [];
    const transport = new FakeTransport(() => ok());
    const audit = new MemoryAudit();
    const guard = new ScopeGuard(
      new ScopeResolver({ dns: new FakeDns({ 'api.exemplo.com': PUBLIC }), now: () => NOW }),
      audit,
    );
    const client = new ScopedHttpClient({
      guard,
      context: programCtx({ rules: { maxRequestsPerSecond: 1000 } }),
      profile: 'passive',
      audit,
      transport,
      now: () => t,
      sleep: async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
    });
    expect(PROFILE_MAX_RPS.passive).toBe(1);
    await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
    await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });
    expect(sleeps).toEqual([1000]);
  });

  it('retry com backoff em timeout; audita cada tentativa', async () => {
    const sleeps: number[] = [];
    const transport = new FakeTransport((_r, n) =>
      n <= 2 ? new TransportError('timeout', 'UND_ERR_CONNECT_TIMEOUT', true) : ok('afinal'),
    );
    const { client, audit } = setup({
      transport,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    const res = await client.request({ method: 'GET', url: 'https://api.exemplo.com/' });

    expect(res.body).toBe('afinal');
    expect(transport.calls).toHaveLength(3);
    expect(sleeps.filter((ms) => ms >= 500)).toEqual([500, 1000]);
    const reqs = audit.entries.filter((e) => e.action === 'http.request');
    expect(reqs.map((e) => e.detail.attempt)).toEqual([0, 1, 2]);
    expect(reqs[0]?.detail).toMatchObject({ status: null, error: 'UND_ERR_CONNECT_TIMEOUT' });
  });

  it('esgota as tentativas e propaga o erro de transporte', async () => {
    const transport = new FakeTransport(() => new TransportError('reset', 'ECONNRESET', true));
    const { client } = setup({ transport, retries: 1 });
    await expect(
      client.request({ method: 'GET', url: 'https://api.exemplo.com/' }),
    ).rejects.toBeInstanceOf(TransportError);
    expect(transport.calls).toHaveLength(2);
  });

  it('não repete método não idempotente nem erro de certificado', async () => {
    const reset = new FakeTransport(() => new TransportError('reset', 'ECONNRESET', true));
    await expect(
      setup({ transport: reset }).client.request({
        method: 'POST',
        url: 'https://api.exemplo.com/',
        body: 'x',
      }),
    ).rejects.toBeInstanceOf(TransportError);
    expect(reset.calls).toHaveLength(1);

    const cert = new FakeTransport(
      () => new TransportError('self signed', 'DEPTH_ZERO_SELF_SIGNED_CERT', false),
    );
    await expect(
      setup({ transport: cert }).client.request({ method: 'GET', url: 'https://api.exemplo.com/' }),
    ).rejects.toBeInstanceOf(TransportError);
    expect(cert.calls).toHaveLength(1);
  });
});
