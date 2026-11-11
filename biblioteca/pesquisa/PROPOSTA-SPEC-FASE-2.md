# PROPOSTA: SPEC-FASE-2 (orquestração e recon)

> **Rascunho para revisão de Edu. Não implementar antes da aprovação.** Se aprovado, mover para `docs/SPEC-FASE-2.md` (contrato de Edu: o agente não edita `docs/SPEC-*.md`). Escrito em 2026-11-11 sobre o código real da fase 1 (`main` em 6236680). Revisão 2 (2026-11-11): D1 decidida (nmap como motor) e roteiro até o teste em laboratório.

Mesmo formato da `SPEC-FASE-1.md`: objetivo, tarefas, artefatos e critérios de aceite verificáveis. Siga `AGENT-GUIDE.md` em paralelo.

## Roteiro até o teste em laboratório

Decisão de Edu (2026-11-11): nenhum teste em laboratório (HTB, THM) até o scanner estar completo, com a lógica de backend pronta e uma GUI utilizável. Até lá, a verificação é automatizada: testes com transporte simulado e, onde preciso, um **lab local de fixtures** (D2). O primeiro scan contra cada alvo real continua sendo aprovado por Edu (`AGENT-GUIDE.md`).

| Etapa | Conteúdo | Situação |
| --- | --- | --- |
| 2a | Orquestração: worker, ciclo de vida, runner, confirmação | **implementada** (feat/fase-2a) |
| 2b | Recon com nmap travado | próxima |
| 3 | Checks web | spec a escrever |
| 4 | Checks de API (OpenAPI) | spec a escrever |
| 5 | Checks de MCP | spec a escrever |
| 6 | Relatório e modo bounty | spec a escrever |
| 7 | Harness de regressão | spec a escrever |
| G | **GUI** (Next.js): ver abaixo | spec a escrever |

**Sobre a GUI.** O `AGENT-GUIDE.md` prevê UI em Next.js (App Router), mas nenhuma fase do roadmap original a cobre. Proponho tratá-la como etapa própria, com spec própria, e começar uma versão mínima logo após a 2b para ver os resultados reais conforme os módulos entram: lista e criação de scans, detalhe com tasks, assets e findings, cadastro de programa, `scope-check`, confirmar e cancelar. A GUI só consome a REST da API (que fica em `127.0.0.1`); não faz rede e não decide escopo.

**Um risco a registrar.** Construir tudo sem nenhum alvo real adia a descoberta de problemas que só aparecem na prática (lab com certificado autoassinado, rotas empurradas pela VPN, formatos de resposta). O lab local de fixtures reduz isso, e cada etapa fecha com `pnpm verify` verde. Mesmo assim, se algo do mundo real quebrar a spec de uma etapa, a revisão volta para cá. Recomendo, no mínimo, um scan de fumaça contra um alvo de lab quando a 2b terminar; a decisão é sua.

## Ponto de partida (o que a fase 1 deixou pronto e o que falta)

Pronto: `ScopeGuard` + `ScopeResolver`, `ScopedHttpClient` (HTTP apenas), `AuditLog` (já com a ação `tool.exec`), `Asset` e `Check` em `packages/core`, `Task` no schema, container `vpn` com kill switch.

Falta, e é o que esta fase constrói:

- **Nenhum worker.** Não há `apps/worker` nem BullMQ. O `createScan` só grava `queued`.
- **Nenhuma forma de descobrir portas.** O `ScopedHttpClient` só fala HTTP e a regra do projeto proíbe `net.connect` fora de `packages/http`. Ver D1 (decidida).
- **Nenhum runner de checks** nem persistência de `Finding`.
- **Nenhum fluxo de confirmação humana**, embora o escopo já devolva `requiresConfirmation` para programas com `automation: unspecified`.

## Fase 2: orquestração e recon

**Objetivo:** um scan sai de `queued`, é executado por um worker dentro do escopo, e termina com `Asset`s (portas, serviços, URLs) e `Finding`s informativos persistidos, tudo auditado.

### Etapa 2a: orquestração

1. **`apps/worker`** (NestJS standalone) com BullMQ e Redis. Filas separadas por modo: `scans-lab` (worker no namespace do `vpn`) e `scans-bounty` (worker sem a VPN de lab, fase 6). Nesta fase só `scans-lab` é ligada.
2. **Resolução de contexto do scan** (`ScanContextLoader`): `platform` htb, thm ou local gera `LabContext` (allowlist de `.ovpn` + `LAB_CIDRS`); `bounty` gera `ProgramContext` a partir do `Program`. Sem contexto resolvível, o scan vai a `failed` com motivo e **nenhum request é feito**.
3. **Ciclo de vida do scan e da task**: `queued` para `running` para `done | failed | canceled`; uma `Task` por módulo; `attempts` e `error` preenchidos; execução idempotente (reexecutar um scan não duplica `Asset` nem `Finding`, usando `dedupKey`).
4. **Runner de checks** em `packages/core` (contrato) e `apps/worker` (execução): registro, filtro por `appliesTo`, timeout por check, isolamento de erro (um check que falha vira `Task.error`, não derruba o scan), persistência de `Finding` com `@@unique([scanId, dedupKey])`.
5. **Confirmação humana**: scan cujo escopo devolve `requiresConfirmation` fica em `queued` até `POST /scans/:id/confirm` (ou `pnpm scan -- confirm <id>`). Exige migração (`Scan.confirmedAt`).
6. **CLI e REST**: `pnpm scan -- run <scanId>` (enfileira), `POST /scans/:id/cancel`, `POST /scans/:id/confirm`; `GET /scans/:id` passa a mostrar progresso real das tasks.

### Etapa 2b: recon com nmap travado (D1 decidida)

7. **`ScopedNmap`** em `packages/http` (junto do cliente HTTP, para manter "rede só aqui"). É a **única** forma de executar o nmap no projeto. Contrato:
   - recebe `{ host, ports, profile, passive }` e passa antes pelo `ScopeGuard`; o nmap **nunca recebe nome de host**, só os **IPs já validados** (`decision.resolvedIps`), o que elimina nova resolução de DNS (rebinding);
   - monta o `argv` a partir de uma lista fechada (abaixo); não há como o chamador passar flag, script ou comando próprio;
   - executa com `spawn` (sem shell), timeout total, saída em XML (`-oX -`), sem escrever arquivo;
   - grava `tool.exec` no `AuditLog` (alvo, IPs, perfil, argv final, duração, código de saída, contagem de portas); nunca grava a saída bruta;
   - falha fechada: se o audit falhar, o nmap não é iniciado.
8. **Parâmetros travados por perfil**

   | Parâmetro | passive | standard | deep |
   | --- | --- | --- | --- |
   | execução do nmap | **não roda** | roda | roda |
   | portas | n/a | `-p` 1 a 1024 + web alternativas + serviços sensíveis (1045) | `-p 1-65535` (todas) |
   | detecção de versão | n/a | `-sV --version-light` | `-sV --version-intensity 7` |
   | taxa | n/a | `--max-rate 50` | `--max-rate 100` |
   | scripts NSE | n/a | `banner,ssl-cert` | `banner,ssl-cert` |

   Sempre presentes: `-sT` (conexão TCP completa pelo sistema, sem pacotes forjados), `--unprivileged`, `-Pn`, `-n`, `--open`, `--max-retries 1`, `--host-timeout` (calculado: `ceil(portas / taxa * 2) + 120 s`, máximo 3600 s) e `-T3`. `--exclude-ports` só aparece quando o `outOfScope` exclui portas.

   > **Revisão 5 (2026-11-11, achado no teste ponta a ponta, ver `FASE-2B.md` D1 e R1):** a tabela aprovada usava `--top-ports 100` e `--top-ports 1000`. O Redis (posição 2935 no ranking do nmap) e o MongoDB (3071) não entram em nenhum dos dois, então `recon.exposed-service` ficava cego para eles. O standard passou a ser uma lista explícita e o deep a varrer todas as portas. O `--host-timeout` fixo (5 e 15 min) também foi trocado por um valor calculado, porque taxa baixa de escopo fazia o nmap desistir do host e devolver vazio. Taxa efetiva é o menor valor entre o perfil e o teto do escopo (`decision.maxRequestsPerSecond`).

   **Nunca permitidos, por construção:** `-sS`, `-sU`, `-O`, `-A`, `--script` fora da lista, categorias `intrusive`, `exploit`, `brute`, `dos`, `vuln`, `fuzzer`, `--script-args`, `-iL`, `-oN/-oG/-oA`, `--spoof-mac`, `-D`, `-S`, `-f`, `--data*`, `--proxies`. Mudar essa lista exige mudar a spec.
9. **Módulo `recon`**: usa o `ScopedHttpClient` e o `ScopedNmap`.

   | Passo | O que faz | Asset gerado | Perfil mínimo |
   | --- | --- | --- | --- |
   | `recon.resolve` | resolve DNS do alvo (A, AAAA, CNAME) | nenhum (vai para o audit) | passive |
   | `recon.http-probe` | `GET /` e `HEAD /` em URL conhecida, via `ScopedHttpClient` | `url` (status, título, headers de servidor) | passive |
   | `recon.port-scan` | `ScopedNmap` nas portas do perfil (timeout próprio de 70 min) | `port` (número, estado, razão) | standard |
   | `recon.service-detect` | produto, versão, CPE e banner vindos do nmap | `service` | standard |
   | `recon.tls-info` | certificado vindo do script `ssl-cert` (assunto, SAN, validade, emissor) | `service` com `tls` | standard |
   | `recon.http-discover` | `GET /` nas portas HTTP(S) encontradas, via `ScopedHttpClient` | `url` | standard |

   **Programa (bounty):** o port scan só roda se `rules.automation` for `allowed` (ou `unspecified` com `confirm`); respeita `ports` da entrada de `inScope` (se a entrada lista portas, só elas são passadas ao nmap, no lugar de `--top-ports`); e fica desligado com `forbidden`. O worker de bounty precisa do seu próprio firewall de saída antes de rodar nmap (fase 6); até lá, o nmap só roda no worker de lab, dentro do namespace do `vpn`.

   **Fora de escopo desta fase:** UDP, SYN scan, fingerprint de SO, enumeração de subdomínios por fonte externa, fuzzing de diretórios, scripts NSE além de `banner` e `ssl-cert`, qualquer envio de payload de teste além do que a detecção de versão do nmap já faz.

### Findings do recon (todos `info` ou `low`, só comprovam, nunca exploram)

| `checkId` | Quando | Severidade |
| --- | --- | --- |
| `recon.tls-expired` | certificado vencido ou com validade menor que 14 dias | low |
| `recon.tls-hostname-mismatch` | nenhum SAN cobre o host | low |
| `recon.http-cleartext` | serviço HTTP em porta padrão sem redirect para HTTPS | info |
| `recon.server-banner` | produto e versão identificados (nmap ou header `Server`) | info |
| `recon.exposed-service` | porta de banco, fila ou administração aberta, só pela porta e pelo serviço detectado | info |

Convenção da biblioteca (FASE-0 D2): `checkId = "<module>.<nome>"`.

### Contratos novos (esboço)

```ts
// packages/core
export interface NmapRequest { host: string; ports?: number[]; profile: 'standard' | 'deep'; passive?: boolean }
export interface ScopedNmap { scan(req: NmapRequest): Promise<NmapResult> }
export interface NmapResult { hosts: Array<{ ip: string; ports: NmapPort[] }>; durationMs: number }
export interface NmapPort { port: number; protocol: 'tcp'; state: 'open'; reason: string;
  service?: { name?: string; product?: string; version?: string; cpe?: string[]; banner?: string };
  tls?: { subject: string; issuer: string; san: string[]; notBefore: string; notAfter: string } }

// Scan ganha: confirmedAt DateTime?  (migração)
// Imagem do worker: Alpine com nmap e nmap-scripts instalados.
```

### Testes obrigatórios

Cada um precisa passar; juntos provam que a fase respeita o escopo.

1. `ScopedNmap` com destino bloqueado (LAN, metadados, fora do `inScope`): lança `ScopeViolationError`, **o nmap não é executado** e só `scope.block` é gravado.
2. O `argv` montado só contém flags da lista fechada, para todos os perfis; teste de tabela que tenta injetar flag, script e host com espaço, e confirma que nada passa.
3. O nmap recebe **IPs, nunca nomes**; um host que resolve para vários IPs gera um alvo por IP, todos validados.
4. A taxa efetiva é o menor entre perfil e escopo (`unspecified` limita a 1/s).
5. `passive` não executa o nmap.
6. Programa: respeita `ports` do `inScope`, e `forbidden` não executa o port scan.
7. `tool.exec` no `AuditLog` sem saída bruta; se o audit falha, o nmap não inicia.
8. Parser de XML do nmap transforma fixtures reais (portas, serviço, versão, certificado) em `Asset`s; XML malformado vira erro tratado, não exceção solta.
9. Scan de lab: `queued` para `done`, com `Asset`s esperados (nmap e transporte simulados).
10. Reexecutar o mesmo scan não duplica `Asset` nem `Finding`.
11. Scan de programa com `automation: unspecified` não executa sem `confirm`; com `confirm`, executa com o teto de taxa do escopo.
12. Scan sem contexto de escopo resolvível termina `failed` sem nenhum `http.request` nem `tool.exec`.
13. Um check que lança exceção vira `Task.error`; os demais checks continuam.
14. `cancel` interrompe o scan entre passos e nenhum request novo sai depois (o processo do nmap em andamento é encerrado).
15. **Integração com Docker** (pulada sem Docker): nmap real contra um container do lab local de fixtures, dentro do firewall do worker; confirma portas e versões esperadas e que um alvo fora da allowlist não é alcançado.
16. Lint e teste de rede: `nmap` só é executado a partir de `packages/http`, e `net.connect` continua proibido fora dele.

### Critérios de aceite da fase 2

- Os 16 testes acima passam em `pnpm verify`.
- Com `docker compose up -d` e o lab local de fixtures, `pnpm scan -- create ...` seguido de `pnpm scan -- run <id>` leva o scan a `done`, e `GET /scans/:id` mostra as tasks concluídas e a contagem de assets.
- O `AuditLog` do scan contém `scope.*`, `http.request` e `tool.exec`, e nenhuma entrada de destino fora do escopo com resultado de conexão.
- Busca no código não encontra `net.connect`, `tls.connect`, `fetch(`, `axios` nem `spawn` de `nmap` fora de `packages/http`.
- Revisão humana de Edu registrada nos PRs (as duas etapas mexem em `packages/http`).

## Decisões (todas fechadas por Edu em 2026-11-11)

> Edu aprovou: **D2** rede do lab local `10.250.0.0/24`; **D3** campo `Scan.confirmedAt`; **D4 a D7** recomendações aceitas. Etapa 2a implementada na branch `feat/fase-2a` (decisões de implementação em `FASE-2A.md`).

**D1. Como descobrir portas: DECIDIDA, nmap travado.** Edu pediu o modo mais viável e com o melhor conjunto de informações. O nmap entrega detecção de serviço e versão, CPE e leitura de certificado, coisas que um probe próprio só alcançaria reimplementando o nmap. O risco que eu apontava (escapar do rate limit e do IP fixado) é tratado assim: só IPs já validados, `argv` de lista fechada sem entrada do chamador, `-sT` sem pacotes forjados, taxa vinda do menor entre perfil e escopo, auditoria `tool.exec` e, no worker de lab, a segunda camada do firewall do `vpn` (default DROP, só `tun+` para os CIDRs do lab). A troca em relação à versão 1 desta proposta: a detecção de versão do nmap envia sondas de protocolo (por exemplo um `GET /` ou um ClientHello), o que vai além de ler o banner. Isso é prática padrão de reconhecimento e não é exploração, mas muda a decisão D5 abaixo.

**D2. Qual é o lab local de fixtures?** O guia cita `pnpm lab:up` (mini lab em `infra/lab`), mas `172.16.0.0/12` é bloqueio absoluto e inclui a rede padrão do Docker (FASE-1, Limites). Recomendação: rede dedicada fora de 172.x e 192.168.x (por exemplo `10.250.0.0/24`), com alvos de teste conhecidos (serviços simples com banners e versões previsíveis, e depois uma aplicação web propositalmente vulnerável para as etapas 3 a 5), e um `worker-local` fora da VPN com firewall próprio que só deixa sair para essa rede.

**D3. `confirm` é um campo no `Scan` (migração) ou um passo só da CLI?** Recomendação: campo `Scan.confirmedAt`, porque a confirmação precisa sobreviver a reinício do worker e aparecer no audit.

**D4. Concorrência.** Proposta: 1 alvo por vez por host; `--max-rate` e timeouts conforme a tabela de perfis; sem retry em porta fechada.

**D5. `recon.exposed-service` deve confirmar o serviço enviando comandos (ex.: `PING` no Redis)? (revisada)** Recomendação mantida: **não**. (Edu confirmou em 2026-11-11 que as sondas de protocolo da detecção de versão do nmap são aceitáveis; comandos de aplicação por conta própria continuam fora.) A detecção de versão do nmap já identifica o serviço; enviar comandos de aplicação a um serviço sem autenticação está na fronteira entre detecção e exploração (regra 5 do guia). Se Edu quiser, vira uma etapa própria com revisão.

**D6. Fonte passiva externa (crt.sh, DNS passivo).** O `ScopeGuard` bloquearia qualquer fonte de terceiro, por desenho. Recomendação: adiar; se for necessário, criar um cliente de fontes passivas com allowlist própria, auditado à parte, e nunca usado para alcançar o alvo.

**D7. Ordem das etapas.** Recomendação: dois PRs, **2a** (worker, ciclo de vida, runner, confirmação) e **2b** (ScopedNmap e recon). Em seguida a GUI mínima, antes das etapas 3 a 5, para ver os resultados reais conforme os módulos entram.
