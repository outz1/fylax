import { lookup, resolveCname } from 'node:dns/promises';
import { normalizeHost } from './destination';

export interface DnsResult {
  addresses: string[];
  /** Cadeia de CNAMEs seguida até o nome final (sem o host original). */
  cnames: string[];
}

export interface DnsResolver {
  resolve(host: string): Promise<DnsResult>;
}

const MAX_CNAME_DEPTH = 8;
const SEM_CNAME = new Set(['ENODATA', 'ENOTFOUND', 'ENOTIMP']);

export class SystemDnsResolver implements DnsResolver {
  async resolve(host: string): Promise<DnsResult> {
    const cnames: string[] = [];
    let current = host;
    for (let i = 0; ; i++) {
      if (i >= MAX_CNAME_DEPTH) throw new Error('cadeia de CNAME longa demais');
      let next: string | undefined;
      try {
        next = (await resolveCname(current))[0];
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code && SEM_CNAME.has(code)) break;
        throw e;
      }
      if (!next) break;
      current = normalizeHost(next);
      cnames.push(current);
    }
    const found = await lookup(host, { all: true, verbatim: true });
    return { addresses: [...new Set(found.map((a) => a.address))], cnames };
  }
}
