import type { AuditEntry, AuditSink, ProgramRules, ScopeEntry } from '@fylax/core';
import type { DnsResolver, DnsResult } from './dns';
import type { ProgramContext } from './types';

/** DNS falso: nenhum teste do projeto faz consulta real. */
export class FakeDns implements DnsResolver {
  constructor(private readonly table: Record<string, DnsResult | Error>) {}

  async resolve(host: string): Promise<DnsResult> {
    const entry = this.table[host];
    if (!entry) throw new Error('ENOTFOUND');
    if (entry instanceof Error) throw entry;
    return entry;
  }
}

export class MemoryAudit implements AuditSink {
  readonly entries: AuditEntry[] = [];

  async record(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  actions(): string[] {
    return this.entries.map((e) => e.action);
  }
}

export const NOW = new Date('2026-11-11T12:00:00Z');

export function daysAgo(days: number): Date {
  return new Date(NOW.getTime() - days * 24 * 60 * 60 * 1000);
}

export function programCtx(over: {
  inScope?: ScopeEntry[];
  outOfScope?: ScopeEntry[];
  rules?: Partial<ProgramRules>;
  reviewedAt?: Date;
}): ProgramContext {
  return {
    mode: 'program',
    program: {
      name: 'exemplo',
      inScope: over.inScope ?? [{ kind: 'wildcard', value: '*.exemplo.com' }],
      outOfScope: over.outOfScope ?? [],
      rules: {
        automation: 'allowed',
        maxRequestsPerSecond: 5,
        testAccountsOnly: false,
        forbidden: [],
        ...over.rules,
      },
      reviewedAt: over.reviewedAt ?? daysAgo(1),
    },
  };
}
