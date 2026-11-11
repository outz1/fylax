# ESTADO (fonte única)

> "Você está aqui". Atualizado pelo /checkpoint. Só números e status destilados; o detalhe mora em `evidencias/` e `biblioteca/`. Substitua as seções de cima; não acumule histórico fora da linha do tempo.

## Você está aqui

- Fase: **fase 0 implementada e verificada**, na branch `feat/fase-0` (local, sem push, sem PR). Aguardando revisão de Edu. Fase 1 não iniciada.
- Últimos números: `pnpm verify` limpo, 25 testes (10 de schema, 4 de serviço com Postgres real, 11 de REST). Os 5 critérios de aceite da fase 0 foram conferidos contra banco e servidor reais.
- Ambiente: Docker Desktop 29.9 em `F:\Docker`, Node 24 (a spec pede 20 LTS; `engines` exige `>=20.12`), pnpm 10.26. Postgres 16 e Redis 7 sobem com `docker compose up -d`. O `.env` local existe (gitignored, senha aleatória); o banco está migrado (`init`) e vazio.

## Próxima ação

1. Edu revisa a branch `feat/fase-0` e decide: push e PR, ou ajustes.
2. Só depois, iniciar a fase 1 (`docs/SPEC-FASE-1.md`, seção "Fase 1"). Ela mexe em `packages/scope`, `packages/http` e `infra/vpn`, que exigem revisão de Edu, e o container de VPN precisa do `.ovpn` do lab (secreto, fornecido por Edu).

## Pendências

- [ ] `docs/AGENT-GUIDE.md` cita `PLANO-SCANNER.md`, que não existe no repositório.
- [ ] `docs/AGENT-GUIDE.md` cita `SPEC-FASE-0-1.md`; o arquivo real é `docs/SPEC-FASE-1.md`. Edu decide qual nome vale.
- [ ] Repositório tem remote `origin` no GitHub; o modelo de ecossistema prevê git 100% local. Edu decide se mantém.
- [ ] Pasta `.dist/` vazia na raiz, sem uso conhecido.
- [ ] Spec pede Node 20 LTS e a máquina tem Node 24; sem `.nvmrc` por ora. Edu decide se fixa a versão.
- [ ] `pnpm dev` só sobe a API (worker e web não existem ainda).

## Linha do tempo

<!-- uma linha por sessão, mais recente no topo: AAAA-MM-DD | o que mudou | commit -->
2026-11-11 | fase 0: monorepo, schema Prisma, API Nest, CLI `scan create`, 25 testes, compose | ver `git log feat/fase-0`
2026-11-10 | ecossistema de contexto criado (CLAUDE.md, ESTADO, biblioteca, evidencias, comunicacao) | aeb3ce5
