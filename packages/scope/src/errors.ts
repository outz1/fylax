import type { ScopeDecision } from './types';

/** Lançado antes de qualquer request quando o Scope Guard bloqueia o destino. */
export class ScopeViolationError extends Error {
  constructor(
    readonly decision: ScopeDecision,
    readonly destination: string,
  ) {
    super(`fora de escopo: ${decision.reason}`);
    this.name = 'ScopeViolationError';
  }
}
