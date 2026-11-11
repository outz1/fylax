import { parseIp, type ParsedIp } from './net';

export interface Destination {
  raw: string;
  host: string;
  /** Porta efetiva: explícita, ou a padrão do esquema. Indefinida para destino sem esquema e sem porta. */
  port?: number;
  scheme?: 'http' | 'https';
  /** Presente quando o destino tem esquema (é uma URL completa). */
  url?: URL;
  ip?: ParsedIp;
}

export type ParsedDestination =
  { ok: true; destination: Destination } | { ok: false; error: string };

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

export function normalizeHost(host: string): string {
  return host
    .replace(/^\[|\]$/g, '')
    .toLowerCase()
    .replace(/\.$/, '');
}

/** Aceita URL http(s) completa ou host/IP simples (com porta opcional). Nunca lança. */
export function parseDestination(input: string): ParsedDestination {
  const raw = input.trim();
  if (!raw) return { ok: false, error: 'destino vazio' };

  const hasScheme = SCHEME.test(raw);
  const bareV6 = !hasScheme && raw.includes(':') && parseIp(raw) ? `[${raw}]` : raw;

  let url: URL;
  try {
    url = new URL(hasScheme ? raw : `http://${bareV6}`);
  } catch {
    return { ok: false, error: 'destino inválido' };
  }

  if (hasScheme && url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: `esquema não permitido: ${url.protocol.replace(':', '')}` };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URL com credenciais embutidas não é permitida' };
  }

  const host = normalizeHost(url.hostname);
  if (!host) return { ok: false, error: 'destino sem host' };

  const scheme = url.protocol === 'https:' ? 'https' : 'http';
  const port = url.port
    ? Number(url.port)
    : hasScheme
      ? scheme === 'https'
        ? 443
        : 80
      : undefined;
  const ip = parseIp(host) ?? undefined;

  return {
    ok: true,
    destination: {
      raw,
      host,
      ...(port !== undefined ? { port } : {}),
      ...(hasScheme ? { scheme, url } : {}),
      ...(ip ? { ip } : {}),
    },
  };
}
