# ESTADO (fonte única)

> "Você está aqui". Atualizado pelo /checkpoint. Só números e status destilados; o detalhe mora em `evidencias/` e `biblioteca/`. Substitua as seções de cima; não acumule histórico fora da linha do tempo.

## Você está aqui

- Fases 0 e 1: **concluídas e mergeadas** no `main` (PR #1 e #2).
- Fase 2 (spec aprovada por Edu em 2026-11-11: `biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md`):
  - **2a (orquestração):** branch `feat/fase-2a`, publicada. PR para revisão.
  - **2b (recon com nmap travado, lab local e endurecimento): implementada e verificada** na branch `feat/fase-2b`, empilhada sobre a 2a. PR para revisão.
- Roteiro combinado com Edu: **nenhum teste em laboratório real (HTB, THM) até o scanner estar completo, com backend pronto e GUI utilizável.** Até lá, verificação automatizada e lab local de fixtures em `10.250.0.0/24`.
- Últimos números: `pnpm verify` limpo com o lab de pé, **241 testes** em 7 pacotes (checks 22, scope 46, queue 5, db 3, api 43, http 87, worker 35). Inclui 4 de integração com nmap real e 3 de kill switch no Docker. O banco termina vazio depois do `verify` (conferido em todas as tabelas).
- Ponta a ponta real da 2b (CLI, Redis, `worker-local` atrás do firewall do `lab-gw`, nmap real, Postgres): as 4 fixtures geram os findings esperados, incluindo Redis 7.4.12 (`recon.exposed-service`), `nginx 1.27.5`, `OpenSSH 9.7` e o certificado autoassinado de 5 dias (`recon.tls-expired`, `recon.tls-hostname-mismatch`). A verificação TLS nunca é contornada.
- **Decisões de Edu em 2026-11-11:** as sondas de protocolo da detecção de versão do nmap são aceitas (comandos de aplicação por conta própria continuam fora); rede do lab local `10.250.0.0/24`; `Scan.confirmedAt`.
- **Desvio da spec aprovada, aplicado na 2b e a confirmar nos PRs:** standard = `-p` 1 a 1024 + web alternativas + `SENSITIVE_PORTS` (1045 portas) e deep = todas as portas, no lugar de `--top-ports 100` e `1000`, que não alcançam Redis (posição 2935) nem MongoDB (3071). `--host-timeout` calculado pela taxa. Detalhe em `FASE-2B.md` (D1 e R1 a R3).
- **Endurecimentos da 2b** (`FASE-2B.md` D14 a D17): portão por check (cancelado, expirado ou terminado não gera mais tráfego nem asset), reaper de scans órfãos, LF em todo o repositório, higiene dos testes.
- Ambiente: Docker Desktop 29.9 em `F:\Docker`, Node 24, pnpm 10.26, `gh` 2.103 instalado (falta autenticar: `gh auth login`). `docker compose up -d` sobe postgres, redis e vpn; `--profile worker` sobe o `worker-lab` (VPN); `pnpm lab:up` sobe o lab local. Banco migrado (`scan_lifecycle`).

## Próxima ação

1. Edu autentica o `gh` (`gh auth login`); abrir os PRs da 2a e da 2b (a 2b tem como base a branch da 2a).
2. Edu revisa. Na 2b, atenção a: `packages/http` (`ScopedNmap`, `nmap-args.ts`), `packages/scope` (modo `portless`), `infra/vpn/entrypoint.sh` (`LOCAL_LAB_CIDR`), `infra/docker-compose.yml` (lab, `lab-gw`, `worker-local`), o portão e o reaper em `apps/worker`.
3. **GUI mínima** (Next.js), antes das etapas web, API e MCP. Precisa de spec própria (a proposta tem o esboço).
4. Etapas 3 a 5 (web, API, MCP): cada uma precisa de spec antes de implementar.
5. Edu fornece o `.ovpn` do lab (`infra/vpn/lab.ovpn`) para testar o OpenVPN real, quando for a hora: é o único trecho da fase 1 não coberto por teste.

## Pendências

- [ ] Mover `PROPOSTA-SPEC-FASE-2.md` para `docs/SPEC-FASE-2.md` (contrato de Edu: o agente não edita `docs/SPEC-*.md`). A implementação segue a proposta aprovada, com o desvio de portas acima.
- [ ] O nmap só roda em worker com firewall (`worker-lab` no vpn e `worker-local`). O worker de bounty precisa do próprio firewall de saída antes (fase 6).
- [ ] Deep (65535 portas) leva ~11 min por host a 100 req/s e é recusado sob taxa baixa de escopo.
- [ ] `scans-bounty` sem worker (fase 6): scan bounty enfileirado fica `queued`.
- [ ] Request HTTP já em andamento quando o check é cancelado termina por conta própria (até 15 s); o portão só impede os novos.
- [ ] OpenVPN real não testado (sem `.ovpn`). Smoke cobre firewall e ausência de `tun0`.
- [ ] Lab com certificado autoassinado falha no cliente HTTP (TLS nunca é desligado). Edu decide como confiar na CA do lab.
- [ ] `FYLAX_LAN_CIDRS` não definido; a LAN atual (192.168.1.0/24) já é coberta pelo padrão 192.168.0.0/16.
- [ ] `docs/AGENT-GUIDE.md` cita `PLANO-SCANNER.md` (inexistente) e `SPEC-FASE-0-1.md` (o real é `docs/SPEC-FASE-1.md`). Edu decide.
- [ ] Repositório tem remote `origin` no GitHub; o modelo de ecossistema prevê git 100% local. Edu decide se mantém.
- [ ] Pasta `.dist/` vazia na raiz, sem uso conhecido.
- [ ] Spec pede Node 20 LTS e a máquina tem Node 24 (`engines`: `>=20.18.1`).

## Linha do tempo

<!-- uma linha por sessão, mais recente no topo: AAAA-MM-DD | o que mudou | commit -->
2026-11-11 | endurecimento: portão por check, reaper de órfãos, LF no repositório, higiene dos testes; 241 testes | ver `git log feat/fase-2b`
2026-11-11 | fase 2b: ScopedNmap, recon (6 checks), lab local 10.250.0.0/24, worker-local, portless | feat/fase-2b
2026-11-11 | fase 2a: worker BullMQ, fila, ciclo de vida, runner, confirm/cancel, worker-lab no vpn | feat/fase-2a
2026-11-11 | proposta de SPEC-FASE-2 revisão 2: nmap travado (D1), roteiro até o lab e GUI | 80f88b6
2026-11-11 | README.md do repositório | 9bc1b12
2026-11-11 | fase 1: Scope Guard, ScopedHttpClient, kill switch (vpn), scope-check, 10 testes de regressão | PR #2
2026-11-11 | fase 0: monorepo, schema Prisma, API Nest, CLI `scan create`, 25 testes, compose | PR #1
2026-11-10 | ecossistema de contexto criado (CLAUDE.md, ESTADO, biblioteca, evidencias, comunicacao) | aeb3ce5
