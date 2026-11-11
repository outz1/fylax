# ESTADO (fonte única)

> "Você está aqui". Atualizado pelo /checkpoint. Só números e status destilados; o detalhe mora em `evidencias/` e `biblioteca/`. Substitua as seções de cima; não acumule histórico fora da linha do tempo.

## Você está aqui

- Fases 0 e 1: **concluídas e mergeadas** no `main` (PR #1 e #2).
- Fase 2 (spec aprovada por Edu em 2026-11-11: `biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md`):
  - **2a (orquestração): implementada e verificada** na branch `feat/fase-2a` (local, **sem push**). Aguarda revisão de Edu.
  - **2b (recon com nmap travado): próxima.** Não iniciada.
- Roteiro combinado com Edu: **nenhum teste em laboratório (HTB, THM) até o scanner estar completo, com backend pronto e GUI utilizável.** Até lá, verificação automatizada e lab local de fixtures em `10.250.0.0/24`.
- Últimos números: `pnpm verify` limpo, **133 testes** (db 3, scope 42, queue 4, api 42, http 26 com 3 de kill switch no Docker, worker 16). Mutação de segurança conferida em 3 guardas do processador (confirmação, fila, cancelamento): uma sobreviveu, foi corrigida e agora é pega.
- Ponta a ponta real (sem mock), na 2a: `create` e `run` pela CLI do host, fila no Redis, `worker-lab` dentro do namespace do `vpn`, scan `done`. Sem `LAB_CIDRS`, o mesmo scan falha fechado e o AuditLog fica vazio (nenhum request).
- Ambiente: Docker Desktop 29.9 em `F:\Docker`, Node 24, pnpm 10.26. `docker compose up -d` sobe postgres, redis e vpn; `--profile worker` sobe o `worker-lab`. Banco migrado (`scan_lifecycle`) e vazio. `.env` local com `LAB_CIDRS=10.250.0.0/24`.

## Próxima ação

1. Edu revisa a branch `feat/fase-2a` (itens que pedem atenção: `packages/scope`, `infra/docker-compose.yml`, `apps/worker`, migração `scan_lifecycle`) e decide o push e o PR.
2. Etapa **2b**: `ScopedNmap` em `packages/http` com `argv` de lista fechada, módulo `recon`, `infra/lab` em `10.250.0.0/24` e teste de integração com nmap real contra as fixtures.
3. **GUI mínima** (Next.js) logo após a 2b, antes das etapas web, API e MCP. Precisa de spec própria.
4. Edu fornece o `.ovpn` do lab (`infra/vpn/lab.ovpn`) para testar o OpenVPN real, quando for a hora: é o único trecho da fase 1 não coberto por teste.

## Pendências

- [ ] Mover `PROPOSTA-SPEC-FASE-2.md` para `docs/SPEC-FASE-2.md` (contrato de Edu: o agente não edita `docs/SPEC-*.md`). A implementação segue a proposta aprovada.
- [ ] Registro de checks vazio: sem checks reais até a 2b; scan de lab termina `done` com `tasks: 0`.
- [ ] `scans-bounty` sem worker (fase 6): scan bounty enfileirado fica `queued`.
- [ ] Sem "reaper": scan `running` sem reentrega do job fica `running` até cancelamento.
- [ ] Check que ignora o `AbortSignal` é abandonado mas pode continuar em segundo plano.
- [ ] OpenVPN real não testado (sem `.ovpn`). Smoke cobre firewall e ausência de `tun0`.
- [ ] Lab com certificado autoassinado falha no cliente (TLS nunca é desligado). Edu decide como confiar na CA do lab.
- [ ] `FYLAX_LAN_CIDRS` não definido; a LAN atual (192.168.1.0/24) já é coberta pelo padrão 192.168.0.0/16.
- [ ] `docs/AGENT-GUIDE.md` cita `PLANO-SCANNER.md` (inexistente) e `SPEC-FASE-0-1.md` (o real é `docs/SPEC-FASE-1.md`). Edu decide.
- [ ] Repositório tem remote `origin` no GitHub; o modelo de ecossistema prevê git 100% local. Edu decide se mantém.
- [ ] Pasta `.dist/` vazia na raiz, sem uso conhecido.
- [ ] Spec pede Node 20 LTS e a máquina tem Node 24 (`engines`: `>=20.18.1`).
- [ ] `gh` não instalado: PRs abertos à mão pelo link que o push devolve.

## Linha do tempo

<!-- uma linha por sessão, mais recente no topo: AAAA-MM-DD | o que mudou | commit -->
2026-11-11 | fase 2a: worker BullMQ, fila, ciclo de vida, runner, confirm/cancel, worker-lab no vpn, 133 testes | ver `git log feat/fase-2a`
2026-11-11 | proposta de SPEC-FASE-2 revisão 2: nmap travado (D1), roteiro até o lab e GUI | 80f88b6
2026-11-11 | README.md do repositório | 9bc1b12
2026-11-11 | fase 1: Scope Guard, ScopedHttpClient, kill switch (vpn), scope-check, 10 testes de regressão | PR #2
2026-11-11 | fase 0: monorepo, schema Prisma, API Nest, CLI `scan create`, 25 testes, compose | PR #1
2026-11-10 | ecossistema de contexto criado (CLAUDE.md, ESTADO, biblioteca, evidencias, comunicacao) | aeb3ce5
