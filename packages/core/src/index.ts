// Contratos do núcleo. Sem lógica: só tipos e listas de valores (fonte única dos enums).

export const TARGET_KINDS = ['host', 'url', 'openapi', 'mcp'] as const;
export type TargetKind = (typeof TARGET_KINDS)[number];

export const TARGET_PLATFORMS = ['htb', 'thm', 'local', 'bounty'] as const;
export type TargetPlatform = (typeof TARGET_PLATFORMS)[number];

export const SCAN_PROFILES = ['passive', 'standard', 'deep', 'bounty'] as const;
export type ScanProfile = (typeof SCAN_PROFILES)[number];

export const SCAN_STATUSES = ['queued', 'running', 'done', 'failed', 'canceled'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const TASK_STATUSES = ['pending', 'running', 'done', 'failed', 'skipped'] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ['low', 'medium', 'high'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const AUTOMATION_POLICIES = ['allowed', 'forbidden', 'unspecified'] as const;
export type AutomationPolicy = (typeof AUTOMATION_POLICIES)[number];

export const CHECK_MODULES = ['recon', 'web', 'api', 'mcp'] as const;
export type CheckModule = (typeof CHECK_MODULES)[number];

export const ASSET_TYPES = ['port', 'service', 'url', 'endpoint', 'tool'] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const SCOPE_ENTRY_KINDS = ['wildcard', 'host', 'urlPrefix', 'cidr'] as const;

export interface ScopeEntry {
  kind: (typeof SCOPE_ENTRY_KINDS)[number];
  /** "*.ex.com" | "api.ex.com" | "https://ex.com/api/*" | "10.129.0.0/16" */
  value: string;
  ports?: number[];
}

export interface ProgramRules {
  automation: AutomationPolicy;
  maxRequestsPerSecond: number;
  requiredHeaders?: Record<string, string>;
  testAccountsOnly: boolean;
  /** ["dos", "bruteforce", "social", "physical"] */
  forbidden: string[];
  /** default 30 */
  reviewMaxAgeDays?: number;
}

export interface Finding {
  checkId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  asset: string;
  description: string;
  evidence: Record<string, unknown>;
  reproduction: string[];
  references: string[];
  dedupKey: string;
}

export interface Asset {
  type: AssetType;
  data: Record<string, unknown>;
}

export interface TargetRef {
  kind: TargetKind;
  value: string;
  platform: TargetPlatform;
  programId?: string;
}

/** Sessão autenticada de teste (conta de teste, nunca credencial real de produção). */
export interface AuthSession {
  label: string;
  headers: Record<string, string>;
}

export interface ScopedRequest {
  method: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** Recon passivo é o único tipo permitido quando automation = forbidden. */
  passive?: boolean;
}

export interface ScopedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  bytes: number;
  /** true se o corpo passou do limite e foi cortado. */
  truncated?: boolean;
  /** Presente quando a resposta é um redirect que não foi seguido. */
  redirect?: { location: string; followed: false; reason: string };
}

export const AUDIT_ACTIONS = ['scope.allow', 'scope.block', 'http.request', 'tool.exec'] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export interface AuditEntry {
  scanId?: string | null;
  action: AuditAction;
  /** Nunca incluir corpo de resposta, valores de header ou valores de query (podem ser segredo). */
  detail: Record<string, unknown>;
}

/** Destino do AuditLog. Se `record` falhar, quem chama NÃO deve enviar tráfego (fail closed). */
export interface AuditSink {
  record(entry: AuditEntry): Promise<void>;
}

/** Destino de assets descobertos durante um scan (já vinculado ao scan). */
export interface AssetSink {
  record(asset: Asset): Promise<void>;
}

/** Única API de rede do projeto. Implementação na fase 1 (packages/http). */
export interface ScopedHttpClient {
  request(req: ScopedRequest): Promise<ScopedResponse>;
}

export interface CheckContext {
  scanId: string;
  target: TargetRef;
  http: ScopedHttpClient;
  assets: Asset[];
  auth?: AuthSession;
}

export interface Check {
  id: string;
  module: CheckModule;
  severity: Severity;
  references: string[];
  appliesTo(asset: Asset): boolean;
  run(ctx: CheckContext): Promise<Finding[]>;
}

export interface ScanSummary {
  id: string;
  targetId: string;
  targetKind: TargetKind;
  targetValue: string;
  platform: TargetPlatform;
  profile: ScanProfile;
  status: ScanStatus;
  createdAt: string;
}

export interface ProgramSummary {
  id: string;
  platform: string;
  name: string;
  briefUrl: string;
  reviewedAt: string;
}
