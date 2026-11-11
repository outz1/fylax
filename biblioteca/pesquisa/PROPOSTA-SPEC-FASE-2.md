# PROPOSTA: SPEC-FASE-2 (recon)

> **Rascunho para revisão de Edu. Não implementar antes da aprovação.** Se aprovado, mover para `docs/SPEC-FASE-2.md` (contrato de Edu: o agente não edita `docs/SPEC-*.md`). Escrito em 2026-11-11 sobre o código real da fase 1 (`main` em 6236680).

Mesmo formato da `SPEC-FASE-1.md`: objetivo, tarefas, artefatos e critérios de aceite verificáveis. Siga `AGENT-GUIDE.md` em paralelo.

## Ponto de partida (o que a fase 1 deixou pronto e o que falta)

Pronto: `ScopeGuard` + `ScopeResolver`, `ScopedHttpClient` (HTTP apenas), `AuditLog`, `Asset` e `Check` em `packages/core`, `Task` no schema, container `vpn` com kill switch.

Falta, e é o que esta fase constrói:

- **Nenhum worker.** Não há `apps/worker` nem BullMQ. O `createScan` só grava `queued`.
- **Nenhuma forma de abrir conexão TCP de forma controlada.** O `ScopedHttpClient` só fala HTTP, e a regra do projeto proíbe `net.connect` fora de `packages/http`. Descobrir portas exige sockets: ver decisão D1.
- **Nenhum runner de checks** nem persistência de `Finding`.
- **Nenhum fluxo de confirmação humana**, embora o escopo já devolva `requiresConfirmation` para programas com `automation: unspecified`.

## Fase 2: orquestração e recon

**Objetivo:** um scan sai de `queued`, é executado por um worker dentro do escopo, e termina com `Asset`s (portas, serviços, URLs) e `Finding`s informativos persistidos, tudo auditado.

### Tarefas

1. **`packages/http`: `ScopedTcpProbe`** (ver D1). Mesma disciplina do `ScopedHttpClient`: `ScopeGuard` antes, IP fixado, rate limit por host, teto por perfil, `AuditLog` (`tcp.connect`). Só conexão e leitura curta de banner; nenhum payload enviado.
2. **`apps/worker`** (NestJS standalone) com BullMQ e Redis. Filas separadas por modo: `scans-lab` (worker no namespace do `vpn`) e `scans-bounty` (worker sem a VPN de lab, fase 6). Nesta fase só `scans-lab` é ligada.
3. **Resolução de contexto do scan** (`ScanContextLoader`): `platform` htb/thm/local gera `LabContext` (allowlist de `.ovpn` + `LAB_CIDRS`); `bounty` gera `ProgramContext` a partir do `Program`. Sem contexto resolvível, o scan vai a `failed` com motivo e **nenhum request é feito**.
4. **Ciclo de vida do scan e da task**: `queued` para `running` para `done | failed | canceled`; uma `Task` por módulo; `attempts` e `error` preenchidos; execução idempotente (reexecutar um scan não duplica `Asset` nem `Finding`, usando `dedupKey`).
5. **Runner de checks** em `packages/core` (contrato) e `apps/worker` (execução): registro de checks, filtro por `appliesTo`, timeout por check, isolamento de erro (um check que falha vira `Task.error`, não derruba o scan), persistência de `Finding` com `@@unique([scanId, dedupKey])`.
6. **Módulo `recon`** (abaixo).
7. **Confirmação humana**: scan cujo escopo devolve `requiresConfirmation` fica em `queued` até `POST /scans/:id/confirm` (ou `pnpm scan -- confirm <id>`). Exige migração (`Scan.confirmedAt`).
8. **CLI e REST**: `pnpm scan -- run <scanId>` (enfileira), `POST /scans/:id/cancel`, `POST /scans/:id/confirm`; `GET /scans/:id` passa a mostrar progresso real das tasks.
9. Testes (abaixo). Todo módulo novo tem teste.

### Módulo recon

Entrada: o `Target` do scan. Saída: `Asset`s e `Finding`s. Cada passo respeita o perfil.

| Passo | O que faz | Asset gerado | Perfil mínimo |
| --- | --- | --- | --- |
| `recon.resolve` | resolve DNS do alvo (A, AAAA, CNAME) | nenhum (vai para o audit) | passive |
| `recon.http-probe` | `GET /` e `HEAD /` em URL conhecida, via `ScopedHttpClient` | `url` (status, título, headers de servidor) | passive |
| `recon.port-connect` | conexão TCP nas portas da lista do perfil, via `ScopedTcpProbe` | `port` (número, estado) | standard |
| `recon.banner` | leitura curta do banner das portas abertas, sem enviar dados | `service` (porta, banner truncado) | standard |
| `recon.http-discover` | `GET /` nas portas HTTP(S) encontradas | `url` | standard |
| `recon.tls-info` | lê o certificado (assunto, SAN, validade, emissor) | `service` com `tls` | standard |

Listas de portas por perfil: `passive` nenhuma além das do alvo; `standard` top 100 portas TCP; `deep` top 1000. Teto de 1 a N conexões simultâneas por host (a definir em D4). **Fora de escopo desta fase:** UDP, SYN scan, fingerprint de SO, enumeração de subdomínios por fonte externa, fuzzing de diretórios, qualquer envio de payload de teste.

### Findings do recon (todos `info` ou `low`, só comprovam, nunca exploram)

| `checkId` | Quando | Severidade |
| --- | --- | --- |
| `recon.tls-expired` | certificado vencido ou com validade menor que 14 dias | low |
| `recon.tls-hostname-mismatch` | nenhum SAN cobre o host (a verificação TLS do cliente permanece ligada; a leitura do certificado usa o probe) | low |
| `recon.http-cleartext` | serviço HTTP em porta padrão sem redirect para HTTPS | info |
| `recon.server-banner` | `Server`/`X-Powered-By` revela produto e versão | info |
| `recon.exposed-service` | porta de banco, fila ou administração aberta (apenas pela porta e banner) | info |

Convenção da biblioteca (FASE-0 D2): `checkId = "<module>.<nome>"`.

### Contratos novos (esboço)

```ts
// packages/core
export interface ScopedTcpProbe {
  connect(req: { host: string; port: number; readBannerBytes?: number; passive?: boolean }): Promise<TcpProbeResult>;
}
export interface TcpProbeResult { open: boolean; banner?: string; tls?: TlsInfo; error?: string }
export interface TlsInfo { subject: string; issuer: string; san: string[]; notBefore: string; notAfter: string }

// AuditAction ganha 'tcp.connect'

// Scan ganha: confirmedAt DateTime?  (migração)
```

### Testes obrigatórios

Cada um precisa passar; juntos provam que a fase respeita o escopo.

1. `ScopedTcpProbe` com destino bloqueado (LAN, metadados, fora do `inScope`): lança `ScopeViolationError`, **nenhum socket é aberto** e só `scope.block` é gravado.
2. `ScopedTcpProbe` revalida o DNS a cada conexão e conecta no IP validado (rebinding): se o nome passar a resolver para a LAN entre a checagem e a conexão, não conecta.
3. Rate limit e teto por perfil também valem para o probe.
4. Scan de lab: `queued` para `done`, com `Asset`s esperados contra um alvo falso (transporte e probe simulados).
5. Reexecutar o mesmo scan não duplica `Asset` nem `Finding`.
6. Scan de programa com `automation: unspecified` não executa sem `confirm`; com `confirm`, executa com o teto de taxa do escopo.
7. Scan de programa com `automation: forbidden` executa só os passos `passive`.
8. Scan sem contexto de escopo resolvível termina `failed` sem nenhum `http.request` nem `tcp.connect` no `AuditLog`.
9. Um check que lança exceção vira `Task.error`; os demais checks do scan continuam.
10. `cancel` interrompe o scan entre passos e nenhum request novo sai depois.
11. Lint e o teste de rede: `net.connect` continua proibido fora de `packages/http` (a exceção é só o diretório do probe).

### Critérios de aceite da fase 2

- Os 11 testes acima passam em `pnpm verify`.
- Com `docker compose up -d` e um alvo de laboratório local, `pnpm scan -- create ...` seguido de `pnpm scan -- run <id>` leva o scan a `done`, e `GET /scans/:id` mostra as tasks concluídas e a contagem de assets.
- O `AuditLog` do scan contém `scope.*`, `http.request` e `tcp.connect`, e **nenhuma entrada** de destino fora do escopo com status de conexão.
- Busca no código não encontra `net.connect`, `tls.connect`, `fetch(` nem `axios` fora de `packages/http`.
- Revisão humana de Edu registrada no PR (a fase mexe em `packages/http`).

## Decisões em aberto (precisam de resposta de Edu antes de implementar)

**D1. Como descobrir portas sem quebrar a regra de rede única?** Recomendação: `ScopedTcpProbe` dentro de `packages/http`, só conexão e leitura de banner, com a mesma disciplina do cliente HTTP. Alternativa: rodar o `nmap` no container `vpn` com alvos já aprovados pelo `ScopeGuard` e auditado como `tool.exec`; é mais completo, mas é um binário externo que escapa do rate limit e do IP fixado, então eu só o aceitaria com os parâmetros travados.

**D2. Qual é o lab local?** O guia cita `pnpm lab:up` (mini lab em `infra/lab`), mas `172.16.0.0/12` é bloqueio absoluto e inclui a rede padrão do Docker (FASE-1, Limites). Recomendação: rede dedicada do lab fora de 172.x e 192.168.x (por exemplo `10.250.0.0/24`), com um `worker-local` fora da VPN e firewall próprio que só deixa sair para essa rede.

**D3. `confirm` é um campo no `Scan` (migração) ou um passo só da CLI?** Recomendação: campo `Scan.confirmedAt`, porque a confirmação precisa sobreviver a reinício do worker e aparecer no audit.

**D4. Concorrência e tetos do probe.** Proposta: 1 conexão simultânea por host em `passive`, 5 em `standard`, 10 em `deep`; timeout de conexão de 3 s; sem retry em porta fechada.

**D5. `recon.exposed-service` deve confirmar o serviço enviando algo (ex.: `PING` no Redis)?** Recomendação: **não**. Só porta aberta e banner. Enviar comandos a um serviço sem autenticação está na fronteira entre detecção e exploração (regra 5 do guia): se Edu quiser, vira uma fase própria com revisão.

**D6. Fonte passiva externa (crt.sh, DNS passivo).** O `ScopeGuard` bloquearia qualquer fonte de terceiro, por desenho. Recomendação: adiar; se for necessário, criar um cliente de fontes passivas com allowlist própria, auditado à parte, e nunca usado para alcançar o alvo.

**D7. Ordem das fases.** Orquestração (tarefas 2 a 5 e 7) é independente do recon. Proposta de dividir em duas PRs: **2a** worker, ciclo de vida, runner e confirmação; **2b** probe e módulo recon.
