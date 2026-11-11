import type { Check, NmapProfile } from '@fylax/core';
import { clean, isHostTarget, str } from '../util';

/** Perfis do scan que rodam nmap. `passive` nunca chega aqui (o runner não seleciona checks ativos). */
export function nmapProfileFor(profile: string): NmapProfile {
  return profile === 'deep' ? 'deep' : 'standard';
}

/**
 * Ativo: port scan e detecção de serviço via ScopedNmap (único caminho para o nmap).
 * Uma execução produz os assets `port` e `service` (versão, CPE, banner e certificado).
 */
export const portScan: Check = {
  id: 'recon.port-scan',
  module: 'recon',
  severity: 'info',
  references: [],
  // Um scan completo em taxa baixa leva muito mais que os 60 s padrão (teto do host-timeout: 1 h).
  timeoutMs: 70 * 60_000,
  appliesTo: isHostTarget,
  async run(ctx) {
    for (const target of ctx.assets.filter(isHostTarget)) {
      const host = str(target.data.host);
      if (!host) continue;

      const result = await ctx.nmap.scan(
        {
          host,
          profile: nmapProfileFor(ctx.profile),
        },
        ctx.signal ? { signal: ctx.signal } : {},
      );

      for (const h of result.hosts) {
        for (const p of h.ports) {
          await ctx.emitAsset({
            type: 'port',
            data: {
              host,
              ip: h.ip,
              port: p.port,
              protocol: p.protocol,
              state: p.state,
              reason: p.reason,
            },
          });
          if (p.service || p.tls) {
            await ctx.emitAsset({
              type: 'service',
              data: clean({
                host,
                ip: h.ip,
                port: p.port,
                name: p.service?.name,
                product: p.service?.product,
                version: p.service?.version,
                extraInfo: p.service?.extraInfo,
                cpe: p.service?.cpe && p.service.cpe.length > 0 ? p.service.cpe : undefined,
                banner: p.service?.banner,
                tunnel: p.service?.tunnel,
                tls: p.tls,
              }),
            });
          }
        }
      }
    }
    return [];
  },
};
