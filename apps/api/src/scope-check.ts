import { readFileSync } from 'node:fs';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import type { ProgramRules, ScopeEntry } from '@fylax/core';
import {
  ScopeGuard,
  ScopeResolver,
  SystemDnsResolver,
  parseOvpnRoutes,
  validateCidr,
  type DnsResolver,
  type ScopeContext,
  type ScopeDecision,
} from '@fylax/scope';
import { NotFoundError, ValidationFailedError } from './errors';
import { parse, programRulesSchema, scopeEntrySchema } from './schemas';
import { PrismaAuditSink } from './sinks';

export interface ScopeCheckArgs {
  destination: string;
  /** Nome de um Program cadastrado. */
  program?: string;
  /** Modo lab: CIDRs explícitos e/ou .ovpn (rotas) e/ou LAB_CIDRS do ambiente. */
  labCidrs?: string[];
  ovpn?: string;
  passive?: boolean;
}

export interface ScopeCheckDeps {
  dns?: DnsResolver;
  env?: NodeJS.ProcessEnv;
}

const csv = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

function issue(path: string, message: string): ValidationFailedError {
  return new ValidationFailedError([{ path, message }]);
}

async function buildContext(
  prisma: PrismaClient,
  args: ScopeCheckArgs,
  env: NodeJS.ProcessEnv,
): Promise<ScopeContext> {
  const labRequested = Boolean(args.ovpn) || (args.labCidrs?.length ?? 0) > 0;

  if (args.program && labRequested) {
    throw issue('--program', 'use --program OU lab (--ovpn / --lab-cidr), não os dois');
  }

  if (args.program) {
    const row = await prisma.program.findUnique({ where: { name: args.program } });
    if (!row) throw new NotFoundError(`Programa "${args.program}" não encontrado`);
    return {
      mode: 'program',
      program: {
        name: row.name,
        inScope: parse(z.array(scopeEntrySchema), row.inScope) as ScopeEntry[],
        outOfScope: parse(z.array(scopeEntrySchema), row.outOfScope) as ScopeEntry[],
        rules: parse(programRulesSchema, row.rules) as ProgramRules,
        reviewedAt: row.reviewedAt,
      },
    };
  }

  const fromOvpn = args.ovpn ? parseOvpnRoutes(readFileSync(args.ovpn, 'utf8')) : [];
  const allowlist = [...new Set([...fromOvpn, ...(args.labCidrs ?? []), ...csv(env.LAB_CIDRS)])];
  if (allowlist.length === 0) {
    throw issue(
      '--program',
      'informe --program <nome> ou um lab (--ovpn <arquivo>, --lab-cidr <cidr> ou LAB_CIDRS no .env)',
    );
  }
  for (const cidr of allowlist) {
    const problema = validateCidr(cidr);
    if (problema) throw issue('--lab-cidr', problema);
  }
  return { mode: 'lab', allowlist };
}

export function formatDecision(destination: string, d: ScopeDecision): string {
  const lines = [
    `decisão: ${d.allowed ? 'ALLOW' : 'BLOCK'}`,
    `destino: ${destination} (host ${d.host}${d.port !== undefined ? `, porta ${d.port}` : ''})`,
    `motivo: ${d.reason}`,
    `regra: ${d.rule ? `${d.rule.kind} ${d.rule.value}` : '(nenhuma)'}`,
    `ips: ${d.resolvedIps.join(', ') || '(nenhum)'}`,
    `cnames: ${d.cnames.join(' -> ') || '(nenhum)'}`,
  ];
  if (d.allowed) {
    lines.push(`requer confirmação humana: ${d.requiresConfirmation ? 'sim' : 'não'}`);
    if (d.maxRequestsPerSecond !== undefined)
      lines.push(`taxa máxima: ${d.maxRequestsPerSecond} req/s`);
  }
  lines.push(
    `nenhum tráfego HTTP foi enviado (só consulta de DNS); decisão gravada no AuditLog como ${d.allowed ? 'scope.allow' : 'scope.block'}.`,
  );
  return lines.join('\n');
}

/**
 * pnpm scan -- scope-check <url> --program <nome>
 * Simula a decisão de escopo sem enviar tráfego HTTP: só consulta DNS e grava scope.* no AuditLog.
 */
export async function scopeCheck(
  prisma: PrismaClient,
  args: ScopeCheckArgs,
  deps: ScopeCheckDeps = {},
): Promise<{ decision: ScopeDecision; text: string }> {
  const env = deps.env ?? process.env;
  const context = await buildContext(prisma, args, env);
  const guard = new ScopeGuard(
    new ScopeResolver({
      dns: deps.dns ?? new SystemDnsResolver(),
      extraBlockedCidrs: csv(env.FYLAX_LAN_CIDRS),
    }),
    new PrismaAuditSink(prisma),
  );
  const decision = await guard.check(args.destination, context, {
    ...(args.passive ? { passive: true } : {}),
  });
  return { decision, text: formatDecision(args.destination, decision) };
}
