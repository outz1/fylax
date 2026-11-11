import type { Asset, Check, CheckContext, Finding, ScopedResponse } from '@fylax/core';
import { clean, finding, isPortService, isUrlTarget, num, str, summarizeResponse } from '../util';

type Safe = { res: ScopedResponse } | { error: string };

/**
 * GET que transforma falha de transporte (timeout, TLS não verificável) em dado, não em erro do check.
 * Violação de escopo e erros inesperados sobem: o runner os registra na task.
 * A verificação TLS nunca é desligada; certificado autoassinado vira `error` no asset.
 */
async function safeGet(ctx: CheckContext, url: string, method: 'GET' | 'HEAD'): Promise<Safe> {
  try {
    return { res: await ctx.http.request({ method, url }) };
  } catch (e) {
    const err = e as { name?: string; code?: string; message?: string };
    if (err.name === 'TransportError') return { error: err.code ?? 'transport-error' };
    throw e;
  }
}

/** Passivo: um GET e um HEAD na URL alvo, via ScopedHttpClient. */
export const httpProbe: Check = {
  id: 'recon.http-probe',
  module: 'recon',
  severity: 'info',
  references: [],
  passive: true,
  appliesTo: isUrlTarget,
  async run(ctx) {
    for (const target of ctx.assets.filter(isUrlTarget)) {
      const url = str(target.data.url);
      if (!url) continue;
      const get = await safeGet(ctx, url, 'GET');
      if ('error' in get) {
        await ctx.emitAsset({ type: 'url', data: { url, via: 'http-probe', error: get.error } });
        continue;
      }
      const head = await safeGet(ctx, url, 'HEAD');
      await ctx.emitAsset({
        type: 'url',
        data: clean({
          url,
          via: 'http-probe',
          ...summarizeResponse(get.res),
          headStatus: 'res' in head ? head.res.status : undefined,
        }),
      });
    }
    return [];
  },
};

const HTTP_CLEARTEXT_PORTS = new Set([80, 8080]);

export const isHttpService = (a: Asset): boolean =>
  isPortService(a) && (str(a.data.name) ?? '').includes('http');

/** Ativo: GET / em cada porta HTTP(S) encontrada pelo port scan. */
export const httpDiscover: Check = {
  id: 'recon.http-discover',
  module: 'recon',
  severity: 'info',
  references: [],
  appliesTo: isHttpService,
  async run(ctx) {
    const findings: Finding[] = [];
    for (const svc of ctx.assets.filter(isHttpService)) {
      const host = str(svc.data.host);
      const port = num(svc.data.port);
      if (!host || port === undefined) continue;

      const tls = svc.data.tunnel === 'ssl' || svc.data.name === 'https';
      const scheme = tls ? 'https' : 'http';
      const defaultPort = tls ? 443 : 80;
      const url = `${scheme}://${host}${port === defaultPort ? '' : `:${port}`}/`;

      const got = await safeGet(ctx, url, 'GET');
      if ('error' in got) {
        await ctx.emitAsset({
          type: 'url',
          data: { url, via: 'http-discover', port, error: got.error },
        });
        continue;
      }
      await ctx.emitAsset({
        type: 'url',
        data: { url, via: 'http-discover', port, ...summarizeResponse(got.res) },
      });

      const redirectsToHttps =
        got.res.status >= 300 &&
        got.res.status < 400 &&
        (got.res.headers['location'] ?? '').toLowerCase().startsWith('https:');
      if (!tls && HTTP_CLEARTEXT_PORTS.has(port) && !redirectsToHttps) {
        findings.push(
          finding({
            checkId: 'recon.http-cleartext',
            title: `HTTP em texto claro sem redirecionamento para HTTPS (${host}:${port})`,
            severity: 'info',
            confidence: 'high',
            asset: `${host}:${port}`,
            description:
              'O serviço responde em HTTP sem criptografia e não redireciona para HTTPS. Credenciais e sessões trafegam em texto claro.',
            evidence: clean({
              url,
              status: got.res.status,
              location: str(got.res.headers['location']),
            }),
            reproduction: [
              `GET ${url}`,
              'Conferir que a resposta não é um redirecionamento (3xx) para https://',
            ],
            references: ['https://cwe.mitre.org/data/definitions/319.html'],
            dedupKey: `recon.http-cleartext:${host}:${port}`,
          }),
        );
      }
    }
    return findings;
  },
};
