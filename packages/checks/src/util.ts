import type { Asset, Finding, ScopedResponse, Severity } from '@fylax/core';

/** Alvo do tipo host (asset de partida do runner). */
export const isHostTarget = (a: Asset): boolean =>
  a.type === 'service' && a.data.target === true && a.data.kind === 'host';

/** Alvo do tipo URL (asset de partida do runner). */
export const isUrlTarget = (a: Asset): boolean =>
  a.type === 'url' && a.data.target === true && a.data.kind === 'url';

/** Serviço descoberto numa porta (exclui o asset de partida do alvo). */
export const isPortService = (a: Asset): boolean =>
  a.type === 'service' && typeof a.data.port === 'number' && typeof a.data.host === 'string';

export const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);
export const num = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

/** Remove chaves undefined: o dedupKey do asset não pode variar por causa delas. */
export function clean<T extends Record<string, unknown>>(obj: T): T {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as T;
}

export function finding(
  f: Omit<Finding, 'references'> & { references?: string[]; severity: Severity },
): Finding {
  return { references: [], ...f };
}

const TITLE = /<title[^>]*>([^<]{0,300})<\/title>/i;

export function htmlTitle(body: string): string | undefined {
  const m = TITLE.exec(body.slice(0, 64 * 1024));
  const title = m?.[1]?.replace(/\s+/g, ' ').trim();
  return title ? title.slice(0, 200) : undefined;
}

/** Campos úteis de uma resposta HTTP para o asset `url`. Nunca guarda o corpo. */
export function summarizeResponse(res: ScopedResponse): Record<string, unknown> {
  return clean({
    status: res.status,
    title: htmlTitle(res.body),
    server: str(res.headers['server']),
    poweredBy: str(res.headers['x-powered-by']),
    contentType: str(res.headers['content-type']),
    location: str(res.headers['location']),
  });
}

export function hostPort(host: string, port: number): string {
  return `${host}:${port}`;
}
