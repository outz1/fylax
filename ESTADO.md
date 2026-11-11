# ESTADO (fonte única)

> "Você está aqui". Atualizado pelo /checkpoint. Só números e status destilados; o detalhe mora em `evidencias/` e `biblioteca/`. Substitua as seções de cima; não acumule histórico fora da linha do tempo.

## Você está aqui

- Fases 0 e 1: **concluídas e mergeadas** no `main` (PR #1 e #2).
- Fase 2 (spec aprovada por Edu em 2026-11-11: `biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md`):
  - **2a (orquestração):** publicada na branch `feat/fase-2a`; PR aguardando abertura e revisão de Edu.
  - **2b (recon com nmap travado + lab local): implementada e verificada** na branch `feat/fase-2b` (local, empilhada sobre a 2a, **sem push**). Aguarda revisão de Edu.
- Roteiro combinado com Edu: **nenhum teste em laboratório real (HTB, THM) até o scanner estar completo, com backend pronto e GUI utilizável.** Até lá, verificação automatizada e lab local de fixtures em `10.250.0.0/24`.
- Últimos números: `pnpm verify` limpo com o lab de pé, **231 testes** (checks 22, scope 46, db 3, queue 5, api 43, http 87, worker 25). Inclui 4 de integração com nmap real e 3 de kill switch no Docker. Mutação de segurança conferida nos checks de decisão (limite de 14 dias do certificado, regra de HTTPS, curinga do SAN): todas pegas.
- **Ponta a ponta real da 2b** (CLI do host, Redis, `worker-local` atrás do firewall do `lab-gw`, nmap real, Postgres): as 4 fixtures foram escaneadas e os findings batem: `recon.http-cleartext` e `recon.server-banner` (nginx 1.27.5), `recon.tls-expired` e `recon.tls-hostname-mismatch` (certificado autoassinado de 5 dias), banner do OpenSSH 9.7, `recon.exposed-service` e `recon.server-banner` do Redis 7.4.12. A verificação TLS não foi contornada (certificado que não valida virou dado no asset).
- **Desvio da spec aprovada, a decidir por Edu:** o ponta a ponta mostrou que `--top-ports 100` (standard) e `--top-ports 1000` (deep) não alcançam Redis (posição 2935 no ranking do nmap) nem MongoDB (3071); o `recon.exposed-service` ficava cego para eles. O standard passou a ser `-p` 1 a 1024 mais portas web alternativas mais `SENSITIVE_PORTS` (1045 portas) e o deep varre todas as portas. O `--host-timeout` também passou a ser calculado pela taxa, porque taxa baixa de escopo fazia o nmap desistir do host e devolver vazio. Detalhe em `biblioteca/pesquisa/FASE-2B.md` (D1 e R1 a R3) e em `PROPOSTA-SPEC-FASE-2.md` (Revisão 5).
- Ambiente: Docker Desktop 29.9 em `F:\Docker`, Node 24, pnpm 10.26. `docker compose up -d` sobe postgres, redis e vpn; `--profile worker` sobe o `worker-lab` (VPN); `pnpm lab:up` sobe o lab local. Banco migrado (`scan_lifecycle`).

## Próxima ação

1. Edu abre o PR da 2a (link e texto prontos) e depois revisa a `feat/fase-2b`. Itens que pedem atenção na 2b: `packages/http` (`ScopedNmap`, `nmap-args.ts`), `packages/scope` (modo `portless`), `infra/vpn/entrypoint.sh` (modo `LOCAL_LAB_CIDR`), `infra/docker-compose.yml` (lab, `lab-gw`, `worker-local`) e a decisão do desvio de portas acima.
2. **GUI mínima** (Next.js), antes das etapas web, API e MCP. Precisa de spec própria (a proposta tem o esboço).
3. Etapas 3 a 5 (web, API, MCP): cada uma precisa de spec antes de implementar.
4. Edu fornece o `.ovpn` do lab (`infra/vpn/lab.ovpn`) para testar o OpenVPN real, quando for a hora: é o único trecho da fase 1 não coberto por teste.

## Pendências

- [ ] Mover `PROPOSTA-SPEC-FASE-2.md` para `docs/SPEC-FASE-2.md` (contrato de Edu: o agente não edita `docs/SPEC-*.md`). A implementação segue a proposta aprovada, com o desvio acima.
- [ ] A detecção de versão do nmap envia sondas de protocolo (`GET /`, ClientHello), além de ler o banner. É prática padrão e não é exploração, mas vai além do que o D5 da proposta descrevia. Edu confirma.
- [ ] O nmap só roda em worker com firewall (`worker-lab` no vpn e `worker-local`). O worker de bounty precisa do próprio firewall de saída antes (fase 6).
- [ ] Deep (65535 portas) leva ~11 min por host a 100 req/s e é recusado sob taxa baixa de escopo.
- [ ] `scans-bounty` sem worker (fase 6): scan bounty enfileirado fica `queued`.
- [ ] Sem "reaper": scan `running` sem reentrega do job fica `running` até cancelamento.
- [ ] Check que ignora o `AbortSignal` é abandonado mas pode continuar em segundo plano.
- [ ] OpenVPN real não testado (sem `.ovpn`). Smoke cobre firewall e ausência de `tun0`.
- [ ] Lab com certificado autoassinado falha no cliente HTTP (TLS nunca é desligado). Edu decide como confiar na CA do lab.
- [ ] `FYLAX_LAN_CIDRS` não definido; a LAN atual (192.168.1.0/24) já é coberta pelo padrão 192.168.0.0/16.
- [ ] `docs/AGENT-GUIDE.md` cita `PLANO-SCANNER.md` (inexistente) e `SPEC-FASE-0-1.md` (o real é `docs/SPEC-FASE-1.md`). Edu decide.
- [ ] Repositório tem remote `origin` no GitHub; o modelo de ecossistema prevê git 100% local. Edu decide se mantém.
- [ ] Pasta `.dist/` vazia na raiz, sem uso conhecido.
- [ ] Spec pede Node 20 LTS e a máquina tem Node 24 (`engines`: `>=20.18.1`).
- [ ] `gh` não instalado: PRs abertos à mão pelo link que o push devolve.

## Linha do tempo

<!-- uma linha por sessão, mais recente no topo: AAAA-MM-DD | o que mudou | commit -->
2026-11-11 | fase 2b: ScopedNmap, recon (6 checks), lab local 10.250.0.0/24, worker-local, portless, 231 testes | ver `git log feat/fase-2b`
2026-11-11 | fase 2a: worker BullMQ, fila, ciclo de vida, runner, confirm/cancel, worker-lab no vpn, 133 testes | feat/fase-2a
2026-11-11 | proposta de SPEC-FASE-2 revisão 2: nmap travado (D1), roteiro até o lab e GUI | 80f88b6
2026-11-11 | README.md do repositório | 9bc1b12
2026-11-11 | fase 1: Scope Guard, ScopedHttpClient, kill switch (vpn), scope-check, 10 testes de regressão | PR #2
2026-11-11 | fase 0: monorepo, schema Prisma, API Nest, CLI `scan create`, 25 testes, compose | PR #1
2026-11-10 | ecossistema de contexto criado (CLAUDE.md, ESTADO, biblioteca, evidencias, comunicacao) | aeb3ce5
