export { ScopeGuard, type GuardOptions } from './guard';
export { ScopeViolationError } from './errors';
export {
  ScopeResolver,
  DEFAULT_REVIEW_MAX_AGE_DAYS,
  UNSPECIFIED_MAX_RPS,
  type ScopeResolverOptions,
} from './resolver';
export { SystemDnsResolver, type DnsResolver, type DnsResult } from './dns';
export { parseOvpnRoutes } from './ovpn';
export { scopeEntrySchema, programRulesSchema } from './schemas';
export {
  ScopeContextError,
  needsConfirmation,
  parseProgramScope,
  resolveScanContext,
  type ProgramRow,
  type ScanContextEnv,
  type ScanContextInput,
} from './context';
export { redactUrl } from './redact';
export { validateCidr, validateScopeEntry } from './validate';
export { ABSOLUTE_BLOCKS } from './net';
export type {
  LabContext,
  ProgramContext,
  ProgramScope,
  ScopeContext,
  ScopeDecision,
  ScopeOptions,
} from './types';
