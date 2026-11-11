import { z } from 'zod';
import type { ProgramRules, ScopeEntry, TargetPlatform } from '@fylax/core';
import { parseOvpnRoutes } from './ovpn';
import { programRulesSchema, scopeEntrySchema } from './schemas';
import type { ProgramScope, ScopeContext } from './types';
import { validateCidr } from './validate';

/** O contexto de escopo de um scan não pôde ser montado: o scan falha e nenhum request é feito. */
export class ScopeContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeContextError';
  }
}

/** Linha de Program como vem do banco (JSON ainda não validado). */
export interface ProgramRow {
  name: string;
  inScope: unknown;
  outOfScope: unknown;
  rules: unknown;
  reviewedAt: Date;
}

export interface ScanContextInput {
  platform: TargetPlatform;
  program?: ProgramRow | null;
}

export interface ScanContextEnv {
  LAB_CIDRS?: string | undefined;
  OVPN_FILE?: string | undefined;
}

const csv = (value: string | undefined): string[] =>
  (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

/** Valida o JSON do banco. Dado inválido nunca vira escopo (fail closed). */
export function parseProgramScope(row: ProgramRow): ProgramScope {
  const parsed = z
    .object({
      inScope: z.array(scopeEntrySchema).min(1),
      outOfScope: z.array(scopeEntrySchema),
      rules: programRulesSchema,
    })
    .safeParse({ inScope: row.inScope, outOfScope: row.outOfScope, rules: row.rules });
  if (!parsed.success) {
    throw new ScopeContextError(`programa "${row.name}" com escopo inválido no banco`);
  }
  return {
    name: row.name,
    inScope: parsed.data.inScope as ScopeEntry[],
    outOfScope: parsed.data.outOfScope as ScopeEntry[],
    rules: parsed.data.rules as ProgramRules,
    reviewedAt: row.reviewedAt,
  };
}

/**
 * Monta o contexto de escopo de um scan.
 * htb, thm e local: allowlist = rotas do .ovpn + LAB_CIDRS. bounty: o Program cadastrado.
 * `readOvpn` devolve o texto do arquivo, ou undefined se não existir.
 */
export function resolveScanContext(
  input: ScanContextInput,
  env: ScanContextEnv,
  readOvpn: (path: string) => string | undefined,
): ScopeContext {
  if (input.platform === 'bounty') {
    if (!input.program) throw new ScopeContextError('scan bounty sem programa cadastrado');
    return { mode: 'program', program: parseProgramScope(input.program) };
  }

  const ovpnPath = env.OVPN_FILE?.trim();
  const ovpnText = ovpnPath ? readOvpn(ovpnPath) : undefined;
  const allowlist = [
    ...new Set([...(ovpnText ? parseOvpnRoutes(ovpnText) : []), ...csv(env.LAB_CIDRS)]),
  ];
  if (allowlist.length === 0) {
    throw new ScopeContextError(
      'sem allowlist de lab: defina LAB_CIDRS ou aponte OVPN_FILE para um .ovpn com linhas route',
    );
  }
  for (const cidr of allowlist) {
    const problema = validateCidr(cidr);
    if (problema) throw new ScopeContextError(`allowlist de lab inválida: ${problema}`);
  }
  return { mode: 'lab', allowlist };
}

/** Programa com automação não especificada exige confirmação humana antes de executar. */
export function needsConfirmation(ctx: ScopeContext): boolean {
  return ctx.mode === 'program' && ctx.program.rules.automation === 'unspecified';
}
