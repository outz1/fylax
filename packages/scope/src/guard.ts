import type { AuditSink } from '@fylax/core';
import { ScopeViolationError } from './errors';
import { redactUrl } from './redact';
import type { ScopeResolver } from './resolver';
import type { ScopeContext, ScopeDecision } from './types';

export interface GuardOptions {
  scanId?: string | null;
  passive?: boolean;
}

/**
 * Resolver + AuditLog. Toda decisão (allow ou block) é gravada como scope.allow / scope.block.
 * Fail closed: se a gravação do audit falhar, o erro sobe e quem chama não envia tráfego.
 */
export class ScopeGuard {
  constructor(
    private readonly resolver: ScopeResolver,
    private readonly audit: AuditSink,
  ) {}

  async check(
    destination: string,
    ctx: ScopeContext,
    options: GuardOptions = {},
  ): Promise<ScopeDecision> {
    const decision = await this.resolver.resolve(destination, ctx, {
      ...(options.passive !== undefined ? { passive: options.passive } : {}),
    });

    await this.audit.record({
      scanId: options.scanId ?? null,
      action: decision.allowed ? 'scope.allow' : 'scope.block',
      detail: {
        destination: /^[a-z][a-z0-9+.-]*:\/\//i.test(destination)
          ? redactUrl(destination)
          : destination.trim(),
        host: decision.host,
        port: decision.port ?? null,
        resolvedIps: decision.resolvedIps,
        cnames: decision.cnames,
        reason: decision.reason,
        rule: decision.rule ?? null,
        mode: ctx.mode,
        program: ctx.mode === 'program' ? ctx.program.name : null,
        passive: options.passive ?? false,
        requiresConfirmation: decision.requiresConfirmation ?? false,
        maxRequestsPerSecond: decision.maxRequestsPerSecond ?? null,
      },
    });
    return decision;
  }

  /** Como `check`, mas lança ScopeViolationError se o destino for bloqueado. */
  async assertAllowed(
    destination: string,
    ctx: ScopeContext,
    options: GuardOptions = {},
  ): Promise<ScopeDecision> {
    const decision = await this.check(destination, ctx, options);
    if (!decision.allowed) throw new ScopeViolationError(decision, destination);
    return decision;
  }
}
