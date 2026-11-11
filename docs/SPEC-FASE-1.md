# Especificação executável: fases 0 e 1

Instruções detalhadas para o agente construir a fundação (fase 0) e a camada de escopo e rede (fase 1). Formato: cada fase tem objetivo, tarefas numeradas, artefatos concretos (schema, contratos) e critérios de aceite verificáveis. Siga `AGENT-GUIDE.md` em paralelo.

As fases 2 a 7 (recon, web, API, MCP, relatório, bounty, harness) serão especificadas no mesmo formato depois que a fase 1 passar na revisão humana. Não as implemente a partir só do `PLANO-SCANNER.md`.

---

## Fase 0: fundação

**Objetivo:** monorepo de pé, banco migrado, tipos do núcleo definidos, CLI mínima que cria um scan.

### Tarefas

1. Inicializar monorepo pnpm com workspaces: `apps/*` e `packages/*`. Configurar TypeScript base (`tsconfig.base.json`, `strict: true`), ESLint, Prettier (sem travessão), Vitest, e o script `pnpm verify`.
2. Criar `docker-compose.yml` em `infra/` com `postgres:16` e `redis:7` (o serviço `vpn` entra na fase 1). Variáveis via `.env` (fornecer `.env.example`).
3. Criar `packages/core` com os tipos e enums abaixo. Sem lógica, só contratos.
4. Criar `apps/api` (NestJS) com Prisma configurado, o schema abaixo, e a primeira migração.
5. Implementar o caso de uso `createScan` e expor via CLI (`pnpm scan -- create --target <valor> --kind <kind>`). Nesta fase o scan só é persistido com status `queued`; nenhum worker ainda.
6. Testes: criação de scan grava no banco; validação de `kind` rejeita entrada inválida.

### Schema Prisma (fase 0)

```prisma
// apps/api/prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum TargetKind { host url openapi mcp }
enum TargetPlatform { htb thm local bounty }
enum ScanProfile { passive standard deep bounty }
enum ScanStatus { queued running done failed canceled }
enum TaskStatus { pending running done failed skipped }
enum Severity { info low medium high critical }
enum Confidence { low medium high }
enum AutomationPolicy { allowed forbidden unspecified }

model Program {
  id            String   @id @default(uuid())
  platform      String
  name          String   @unique
  briefUrl      String
  inScope       Json     // ScopeEntry[]
  outOfScope    Json     // ScopeEntry[]
  rules         Json     // ProgramRules
  reviewedAt    DateTime
  createdAt     DateTime @default(now())
  targets       Target[]
}

model Target {
  id         String         @id @default(uuid())
  kind       TargetKind
  value      String
  platform   TargetPlatform
  programId  String?
  program    Program?       @relation(fields: [programId], references: [id])
  createdAt  DateTime       @default(now())
  scans      Scan[]
  @@unique([kind, value, platform])
}

model Scan {
  id         String      @id @default(uuid())
  targetId   String
  target     Target      @relation(fields: [targetId], references: [id])
  profile    ScanProfile
  status     ScanStatus  @default(queued)
  startedAt  DateTime?
  finishedAt DateTime?
  createdAt  DateTime    @default(now())
  tasks      Task[]
  assets     Asset[]
  findings   Finding[]
}

model Task {
  id        String     @id @default(uuid())
  scanId    String
  scan      Scan       @relation(fields: [scanId], references: [id])
  module    String     // recon | web | api | mcp
  status    TaskStatus @default(pending)
  attempts  Int        @default(0)
  error     String?
  createdAt DateTime   @default(now())
}

model Asset {
  id        String   @id @default(uuid())
  scanId    String
  scan      Scan     @relation(fields: [scanId], references: [id])
  type      String   // port | service | url | endpoint | tool
  data      Json
  createdAt DateTime @default(now())
}

model Finding {
  id           String     @id @default(uuid())
  scanId       String
  scan         Scan       @relation(fields: [scanId], references: [id])
  checkId      String
  title        String
  severity     Severity
  confidence   Confidence
  asset        String
  description  String
  evidence     Json
  reproduction String[]
  references   String[]
  dedupKey     String
  falsePositive Boolean   @default(false)
  createdAt    DateTime   @default(now())
  @@unique([scanId, dedupKey])
}

model AuditLog {       // toda decisão do Scope Guard e toda ação de rede
  id        String   @id @default(uuid())
  scanId    String?
  action    String   // scope.allow | scope.block | http.request | tool.exec
  detail    Json
  createdAt DateTime @default(now())
  @@index([scanId])
}
```

### Tipos do core (`packages/core`)

```ts
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export interface ScopeEntry {
  kind: 'wildcard' | 'host' | 'urlPrefix' | 'cidr';
  value: string;        // "*.ex.com" | "api.ex.com" | "https://ex.com/api/*" | "10.129.0.0/16"
  ports?: number[];
}

export interface ProgramRules {
  automation: 'allowed' | 'forbidden' | 'unspecified';
  maxRequestsPerSecond: number;
  requiredHeaders?: Record<string, string>;
  testAccountsOnly: boolean;
  forbidden: string[];          // ["dos","bruteforce","social","physical"]
  reviewMaxAgeDays?: number;    // default 30
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

export interface Check {
  id: string;
  module: 'recon' | 'web' | 'api' | 'mcp';
  severity: Severity;
  references: string[];
  appliesTo(asset: Asset): boolean;
  run(ctx: CheckContext): Promise<Finding[]>;
}
// Asset, CheckContext, ScopedHttpClient, AuthSession: definir junto.
```

### Contratos REST (fase 0, implementar o mínimo)

```
POST /scans            body { targetKind, targetValue, platform, profile } -> 201 { scanId }
GET  /scans            -> 200 { scans: ScanSummary[] }
GET  /scans/:id        -> 200 { scan, tasks, assetCount, findingCount }
GET  /scans/:id/findings?severity=&module= -> 200 { findings: Finding[] }
POST /programs         body { ...ProgramYaml }     -> 201 { programId }   (validação na fase 6/bounty)
GET  /programs         -> 200 { programs: ProgramSummary[] }
```

Validação de entrada com Zod ou class-validator em todo endpoint. Rejeitar `platform: bounty` sem `programId`.

### Critérios de aceite da fase 0

- `pnpm install && pnpm verify` passa limpo.
- `docker compose up -d` sobe postgres e redis; `pnpm db:migrate` aplica a migração.
- `pnpm scan -- create --target 10.129.0.10 --kind host --platform htb` grava um `Scan` com status `queued` e imprime o `scanId`.
- `GET /scans/:id` retorna o scan criado.
- Entrada com `kind` inválido retorna erro de validação, não 500.

---

## Fase 1: escopo e rede (o coração de segurança)

**Objetivo:** garantir, em duas camadas independentes, que nenhum request sai para fora do alvo autorizado. Esta fase é revisada por Edu antes de qualquer uso real.

### Tarefas

1. `packages/scope`: implementar o `ScopeResolver`, que decide allow/block para um destino, dado o contexto (lab allowlist ou `Program`).
2. `packages/http`: implementar o `ScopedHttpClient`, único meio de fazer requisição no projeto. Ele consulta o `ScopeResolver` antes de cada request, aplica rate limit e grava `AuditLog`.
3. `infra/vpn`: container OpenVPN com kill switch por firewall. Workers usam `network_mode: "service:vpn"`.
4. CLI `pnpm scan -- scope-check <url> --program <nome>`: simula a decisão de escopo sem enviar tráfego.
5. Testes de regressão de escopo (abaixo). São o critério de aceite mais importante.

### Lógica do ScopeResolver

Entrada: destino (URL ou IP), contexto (`lab` com CIDRs da allowlist, ou `program` com `inScope`/`outOfScope`/`rules`). Saída: `{ allowed: boolean, reason: string, rule?: ScopeEntry }`.

Ordem de avaliação (a primeira que decidir vence):

1. Resolver DNS do host para IP(s). Se falhar, **block** (não arrisca).
2. **Bloqueio absoluto**, em qualquer modo: loopback, link-local, metadados de cloud (169.254.169.254), e a LAN de Edu. Nunca liberável.
3. Modo lab: IP resolvido precisa cair em um CIDR da allowlist do `.ovpn`. Fora disso, block.
4. Modo program:
   - Se bater em `outOfScope`, **block** (fora de escopo sempre vence).
   - Se `rules.automation === 'forbidden'`, só liberar requests marcados como recon passivo; o resto block.
   - Se `reviewedAt` mais velho que `reviewMaxAgeDays` (default 30), block com motivo "brief precisa de nova revisão".
   - Liberar só se bater em `inScope` (wildcard, host, urlPrefix ou cidr, com porta quando especificada). Host de terceiro só passa se listado explicitamente.
   - `automation === 'unspecified'`: liberar com teto de taxa baixo e marcar o scan como "requer confirmação".
5. Default: **block**. Toda decisão vai para `AuditLog`, com o motivo e a regra.

Redirects: o `ScopedHttpClient` nunca segue redirect automaticamente. Ele revalida o destino do `Location` pelo `ScopeResolver`; se bloquear, registra como asset e para.

### ScopedHttpClient

- Única API de rede do projeto. Nenhum check abre socket direto (lint/review barra `fetch`/`http` fora deste pacote).
- Antes de cada request: consulta `ScopeResolver`; se block, lança `ScopeViolationError` e grava audit.
- Rate limit por alvo (token bucket), teto vindo do perfil ou de `rules.maxRequestsPerSecond`.
- Aplica `requiredHeaders` do programa em toda requisição.
- Timeout, retry com backoff (para timeout de VPN e reset de máquina), e limite de redirects (revalidados).
- Grava cada request no `AuditLog` (`http.request`): método, URL, status, bytes, decisão de escopo.

### Rede (infra/vpn)

- Container `vpn` com `cap_add: NET_ADMIN`, device `/dev/net/tun`, lê o `.ovpn` montado read-only.
- Firewall no container: saída permitida só pela `tun0` para os CIDRs do lab e para o endpoint do servidor VPN. Default drop. Se a `tun0` cair, nada sai (kill switch).
- Workers: `network_mode: "service:vpn"`. Postgres e Redis em rede interna, sem porta publicada além do necessário.
- Modo bounty (fase 6): worker separado (`worker-bounty`) que **não** usa a VPN de lab; sai pela conexão direta ou VPS. Filas separadas por modo.

### Testes de regressão de escopo (obrigatórios)

Cada um precisa passar; são a prova de que a camada funciona:

1. Destino em CIDR da allowlist de lab: **allow**.
2. Destino fora da allowlist (IP público qualquer): **block**.
3. Host que resolve para a LAN de Edu: **block**, mesmo se alguém o listar no escopo.
4. Metadados de cloud (169.254.169.254): **block** sempre.
5. Programa: host em `inScope` wildcard: **allow**; o mesmo host em `outOfScope`: **block**.
6. Host de terceiro não listado (via CNAME de subdomínio in-scope): **block**.
7. `automation: forbidden`: request ativo **block**, recon passivo **allow**.
8. `reviewedAt` com 40 dias e `reviewMaxAgeDays: 30`: **block**.
9. Redirect de alvo in-scope para destino out-of-scope: não seguido, registrado como asset.
10. Teste de fumaça de rede: com o container `vpn` sem `tun0` ativa, um request do worker falha (kill switch), não vaza pela rota padrão.

### Critérios de aceite da fase 1

- Os 10 testes acima passam em `pnpm verify`.
- `pnpm scan -- scope-check https://api.exemplo.com --program exemplo` imprime a decisão e a regra, sem gerar tráfego (confirmável porque não há entrada `http.request` no audit, só `scope.*`).
- Busca no código não encontra `fetch(`, `axios`, `http.request` ou `net.connect` fora de `packages/http`.
- Revisão humana de Edu registrada no PR antes do merge.

---

## Depois da fase 1

Ao passar a fase 1, me peça (ou a outro agente) a `SPEC-FASE-2.md` (recon). Especificar os módulos antes da fundação existir só gera retrabalho, porque a forma real do `Asset` e do `ScopedHttpClient` ajusta a spec dos checks.