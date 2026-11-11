import type { ScopeEntry } from '@fylax/core';
import { parseDestination } from './destination';
import type { DnsResolver } from './dns';
import { matchesInScope, matchesOutOfScope, nameInList, type Target } from './matching';
import { absoluteBlock, inCidr, ipToString, parseCidr, parseIp, type ParsedIp } from './net';
import type { ProgramContext, ScopeContext, ScopeDecision, ScopeOptions } from './types';

export const DEFAULT_REVIEW_MAX_AGE_DAYS = 30;
/** Teto de taxa quando o programa não especifica política de automação. */
export const UNSPECIFIED_MAX_RPS = 1;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface ScopeResolverOptions {
  dns: DnsResolver;
  /** Faixas extras da LAN do operador (FYLAX_LAN_CIDRS), somadas ao bloqueio absoluto padrão. */
  extraBlockedCidrs?: readonly string[];
  now?: () => Date;
}

type Base = Pick<ScopeDecision, 'host' | 'port' | 'resolvedIps' | 'cnames'>;

/**
 * Decide allow/block para um destino. Ordem (a primeira que decidir vence):
 * 1. DNS (falhou: block)  2. bloqueio absoluto  3. modo lab  4. modo program  5. default block.
 * Nunca lança por causa do destino: todo problema vira uma decisão de block com motivo.
 */
export class ScopeResolver {
  constructor(private readonly opts: ScopeResolverOptions) {}

  async resolve(
    destination: string,
    ctx: ScopeContext,
    options: ScopeOptions = {},
  ): Promise<ScopeDecision> {
    const parsed = parseDestination(destination);
    if (!parsed.ok) {
      return {
        allowed: false,
        reason: parsed.error,
        host: destination.trim(),
        resolvedIps: [],
        cnames: [],
      };
    }
    const dest = parsed.destination;
    const hostPort = { host: dest.host, ...(dest.port !== undefined ? { port: dest.port } : {}) };

    // 1. DNS
    let addresses: string[];
    let cnames: string[] = [];
    if (dest.ip) {
      addresses = [ipToString(dest.ip)];
    } else {
      try {
        const r = await this.opts.dns.resolve(dest.host);
        addresses = r.addresses;
        cnames = r.cnames;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return block(
          { ...hostPort, resolvedIps: [], cnames },
          `falha ao resolver DNS de ${dest.host}: ${msg}`,
        );
      }
    }

    const ips: ParsedIp[] = [];
    for (const a of addresses) {
      const ip = parseIp(a);
      if (!ip)
        return block({ ...hostPort, resolvedIps: [], cnames }, `resposta de DNS inválida: ${a}`);
      ips.push(ip);
    }
    const base: Base = { ...hostPort, resolvedIps: ips.map(ipToString), cnames };
    if (ips.length === 0) return block(base, `DNS sem endereços para ${dest.host}`);

    // 2. Bloqueio absoluto (nunca liberável, em qualquer modo)
    for (const ip of ips) {
      const hit = absoluteBlock(ip, this.opts.extraBlockedCidrs);
      if (hit) {
        return block(base, `bloqueio absoluto: ${ipToString(ip)} em ${hit.label}`, {
          kind: 'cidr',
          value: hit.cidr,
        });
      }
    }

    const target: Target = { dest, ips };

    // 3. Modo lab
    if (ctx.mode === 'lab') return this.decideLab(base, ips, ctx.allowlist);

    // 4. Modo program
    return this.decideProgram(base, target, ctx, options);
  }

  private decideLab(base: Base, ips: ParsedIp[], allowlist: readonly string[]): ScopeDecision {
    const cidrs = allowlist.map((c) => ({ raw: c, parsed: parseCidr(c) })).filter((c) => c.parsed);
    let firstRule: ScopeEntry | undefined;
    for (const ip of ips) {
      const hit = cidrs.find((c) => c.parsed && inCidr(ip, c.parsed));
      if (!hit) {
        return block(base, `${ipToString(ip)} fora da allowlist do lab`);
      }
      firstRule ??= { kind: 'cidr', value: hit.raw };
    }
    return {
      allowed: true,
      reason: `dentro da allowlist do lab (${firstRule?.value})`,
      ...(firstRule ? { rule: firstRule } : {}),
      ...base,
    };
  }

  private decideProgram(
    base: Base,
    target: Target,
    ctx: ProgramContext,
    options: ScopeOptions,
  ): ScopeDecision {
    const { program } = ctx;
    const { rules } = program;

    // a. Fora de escopo sempre vence.
    const excluded = program.outOfScope.find((e) => matchesOutOfScope(e, target, base.cnames));
    if (excluded) {
      return block(
        base,
        `fora de escopo do programa "${program.name}" (outOfScope: ${excluded.value})`,
        excluded,
      );
    }

    // b. Automação proibida: só recon passivo.
    if (rules.automation === 'forbidden' && !options.passive) {
      return block(
        base,
        `programa "${program.name}" proíbe automação: só recon passivo é permitido`,
      );
    }

    // c. Brief vencido.
    const maxAge = rules.reviewMaxAgeDays ?? DEFAULT_REVIEW_MAX_AGE_DAYS;
    const ageDays = Math.floor(
      ((this.opts.now?.() ?? new Date()).getTime() - program.reviewedAt.getTime()) / DAY_MS,
    );
    if (ageDays > maxAge) {
      return block(
        base,
        `brief precisa de nova revisão (revisado há ${ageDays} dias, máximo ${maxAge})`,
      );
    }

    // d. Host de terceiro só passa se listado explicitamente: todo nome da cadeia de CNAME precisa estar em escopo.
    for (const cname of base.cnames) {
      if (!nameInList(program.inScope, cname)) {
        return block(base, `CNAME para host de terceiro não listado no escopo: ${cname}`);
      }
    }

    // e. Liberar só se bater em inScope.
    const rule = program.inScope.find((e) => matchesInScope(e, target));
    if (!rule) return block(base, `${base.host} não está listado em inScope (default: block)`);

    // f. Taxa e confirmação.
    if (rules.automation === 'unspecified') {
      return {
        allowed: true,
        reason: `em escopo (${rule.value}); automação não especificada: taxa reduzida e confirmação humana necessárias`,
        rule,
        requiresConfirmation: true,
        maxRequestsPerSecond: Math.min(rules.maxRequestsPerSecond, UNSPECIFIED_MAX_RPS),
        ...base,
      };
    }
    return {
      allowed: true,
      reason: `em escopo (${rule.value})`,
      rule,
      maxRequestsPerSecond: rules.maxRequestsPerSecond,
      ...base,
    };
  }
}

function block(base: Base, reason: string, rule?: ScopeEntry): ScopeDecision {
  return { allowed: false, reason, ...(rule ? { rule } : {}), ...base };
}
