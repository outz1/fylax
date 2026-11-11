import type { ProgramRules, ScopeEntry } from '@fylax/core';

export interface ProgramScope {
  name: string;
  inScope: ScopeEntry[];
  outOfScope: ScopeEntry[];
  rules: ProgramRules;
  reviewedAt: Date;
}

/** Lab: o IP resolvido precisa cair em um CIDR da allowlist (derivada do .ovpn). */
export interface LabContext {
  mode: 'lab';
  allowlist: string[];
}

export interface ProgramContext {
  mode: 'program';
  program: ProgramScope;
}

export type ScopeContext = LabContext | ProgramContext;

export interface ScopeDecision {
  allowed: boolean;
  reason: string;
  rule?: ScopeEntry;
  host: string;
  port?: number;
  resolvedIps: string[];
  cnames: string[];
  /** automation = unspecified: o scan precisa de confirmação humana. */
  requiresConfirmation?: boolean;
  /** Teto de taxa imposto pelo escopo (programas). */
  maxRequestsPerSecond?: number;
  /** Modo portless: portas que `outOfScope` exclui para este host. */
  excludedPorts?: number[];
}

export interface ScopeOptions {
  /** Recon passivo é o único tipo permitido quando automation = forbidden. */
  passive?: boolean;
  /**
   * Destino é só o host (port scan): decide se o host está em escopo para alguma porta e devolve
   * as portas permitidas (`rule.ports`) e as excluídas (`excludedPorts`). Usado só pelo nmap.
   */
  portless?: boolean;
}
