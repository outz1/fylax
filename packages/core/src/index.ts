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

export const AUDIT_ACTIONS = [
  'scope.allow',
  'scope.block',
  'http.request',
  'tool.exec',
  'scan.confirm',
  'scan.cancel',
] as const;
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

/**
 * Portas de banco, cache, busca e administração remota. Dono único desta lista: o port scan
 * (packages/http) garante que o perfil standard as inclua, e `recon.exposed-service` as usa para
 * classificar. Redis, MongoDB e Memcached ficam muito abaixo do top-1000 do nmap (posições 2935,
 * 3071 e 6388), então não dá para confiar em `--top-ports` para encontrá-los.
 */
export const SENSITIVE_PORTS: Readonly<Record<number, string>> = {
  23: 'administração remota',
  1433: 'banco de dados',
  1521: 'banco de dados',
  2375: 'administração de containers',
  3306: 'banco de dados',
  3389: 'administração remota (RDP)',
  5432: 'banco de dados',
  5900: 'administração remota',
  5984: 'banco de dados',
  6379: 'banco de dados',
  9042: 'banco de dados',
  9200: 'índice de busca',
  11211: 'cache',
  27017: 'banco de dados',
};

export const NMAP_PROFILES = ['standard', 'deep'] as const;
export type NmapProfile = (typeof NMAP_PROFILES)[number];

export interface NmapRequest {
  /** Nome ou IP. O nmap nunca recebe o nome: só os IPs que o Scope Guard validou. */
  host: string;
  /** Opcional e só reduz: nunca amplia as portas do perfil nem as do escopo. */
  ports?: number[];
  profile: NmapProfile;
}

export interface TlsInfo {
  subject: string;
  issuer: string;
  san: string[];
  notBefore: string;
  notAfter: string;
}

export interface NmapServiceInfo {
  name?: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  cpe: string[];
  /** Saída do script `banner`, truncada. */
  banner?: string;
  /** "ssl" quando o serviço fala TLS (https, imaps, etc.). */
  tunnel?: 'ssl';
}

export interface NmapPort {
  port: number;
  protocol: 'tcp';
  state: 'open';
  reason: string;
  service?: NmapServiceInfo;
  tls?: TlsInfo;
}

export interface NmapHost {
  ip: string;
  ports: NmapPort[];
}

export interface NmapResult {
  hosts: NmapHost[];
  durationMs: number;
}

/** Única forma de executar o nmap no projeto. Implementação em packages/http. */
export interface ScopedNmap {
  scan(req: NmapRequest, opts?: { signal?: AbortSignal }): Promise<NmapResult>;
}

export interface CheckContext {
  scanId: string;
  target: TargetRef;
  profile: ScanProfile;
  http: ScopedHttpClient;
  /** Port scan e detecção de serviço. Recusa execução em perfil passivo. */
  nmap: ScopedNmap;
  /** Assets conhecidos até agora (inclui os emitidos por checks anteriores). */
  assets: Asset[];
  /** Persiste (sem duplicar) e disponibiliza o asset para os checks seguintes. */
  emitAsset(asset: Asset): Promise<void>;
  /** Dispara quando o scan é cancelado ou o check estoura o timeout. */
  signal?: AbortSignal;
  auth?: AuthSession;
}

export interface Check {
  /** "<módulo>.<nome>" (ex.: "recon.tls-expired"); o runner rejeita findings fora do módulo. */
  id: string;
  module: CheckModule;
  severity: Severity;
  references: string[];
  /** true: só recon passivo (roda no perfil passive e nunca faz request ativo). Padrão: ativo. */
  passive?: boolean;
  /** Tempo máximo deste check (ms). Sem valor, vale o padrão do runner (60 s). O port scan pede mais. */
  timeoutMs?: number;
  appliesTo(asset: Asset): boolean;
  run(ctx: CheckContext): Promise<Finding[]>;
}

/**
 * Uma fila por ambiente de rede, para que um scan nunca caia num worker que alcança outra rede:
 * - lab: HTB e THM, worker no namespace do vpn (kill switch);
 * - local: lab local de fixtures (10.250.0.0/24), worker com firewall próprio;
 * - bounty: worker sem a VPN de lab (fase 6).
 */
export const SCAN_QUEUES = {
  lab: 'scans-lab',
  local: 'scans-local',
  bounty: 'scans-bounty',
} as const;
export type ScanQueueName = (typeof SCAN_QUEUES)[keyof typeof SCAN_QUEUES];

export interface ScanJob {
  scanId: string;
}

export function queueForPlatform(platform: TargetPlatform): ScanQueueName {
  if (platform === 'bounty') return SCAN_QUEUES.bounty;
  if (platform === 'local') return SCAN_QUEUES.local;
  return SCAN_QUEUES.lab;
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
