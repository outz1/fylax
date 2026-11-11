# ESTADO (fonte única)

> "Você está aqui". Atualizado pelo /checkpoint. Só números e status destilados; o detalhe mora em `evidencias/` e `biblioteca/`. Substitua as seções de cima; não acumule histórico fora da linha do tempo.

## Você está aqui

- Fase 0: **concluída e mergeada** no `main` (PR #1).
- Fase 1: **concluída e mergeada** no `main` (PR #2). Fase 2: **bloqueada aguardando spec**; proposta em `biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md`.
- Últimos números: `pnpm verify` limpo, 92 testes (scope 35, http 26 incluindo 3 de kill switch com Docker, api 31). Critérios de aceite da fase 1 conferidos (ver abaixo).
- Ambiente: Docker Desktop 29.9 em `F:\Docker`, Node 24, pnpm 10.26. `docker compose up -d` sobe postgres, redis e vpn (vpn fica fechado e não saudável sem `infra/vpn/lab.ovpn`). Banco migrado (`init`) e vazio.

### Critérios de aceite da fase 1

- [x] Os 10 testes de regressão de escopo passam em `pnpm verify` (1 a 8 em `packages/scope`, 9 em `packages/http/src/client.test.ts`, 10 em `packages/http/src/killswitch.smoke.test.ts`).
- [x] `pnpm scan -- scope-check <alvo> --program exemplo` imprime decisão e regra; o AuditLog ficou só com `scope.*` e 0 entradas `http.request`.
- [x] Busca no código não encontra `fetch(`, `axios`, `http.request`, `net.connect` nem TLS desabilitado fora de `packages/http` (teste automático, validado com uma violação plantada).
- [x] Revisão humana de Edu registrada (PR #2 aprovado e mergeado).

## Próxima ação

1. Edu revisa `biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md`, responde as decisões D1 a D7 e, se aprovar, move o arquivo para `docs/SPEC-FASE-2.md`. Só então a fase 2 começa.
2. Edu fornece o `.ovpn` do lab (`infra/vpn/lab.ovpn`) e `LAB_CIDRS` no `.env` para testar o OpenVPN real: é o único trecho da fase 1 não coberto por teste.

## Pendências

- [ ] OpenVPN real não testado (sem `.ovpn`). Smoke cobre firewall e ausência de `tun0`.
- [ ] Lab com certificado autoassinado falha no cliente (TLS nunca é desligado). Edu decide como confiar na CA do lab.
- [ ] 172.16.0.0/12 é bloqueio absoluto e inclui a bridge do Docker: lab local em container (172.x) ficaria bloqueado. Edu decide a faixa.
- [ ] `FYLAX_LAN_CIDRS` não está definido; a LAN atual (192.168.1.0/24) já é coberta pelo padrão 192.168.0.0/16.
- [ ] `docs/AGENT-GUIDE.md` cita `PLANO-SCANNER.md`, que não existe no repositório.
- [ ] `docs/AGENT-GUIDE.md` cita `SPEC-FASE-0-1.md`; o arquivo real é `docs/SPEC-FASE-1.md`. Edu decide qual nome vale.
- [ ] Repositório tem remote `origin` no GitHub; o modelo de ecossistema prevê git 100% local. Edu decide se mantém.
- [ ] Pasta `.dist/` vazia na raiz, sem uso conhecido.
- [ ] Spec pede Node 20 LTS e a máquina tem Node 24; `undici` 7 pede Node `>=20.18.1` (ajustar `engines`).
- [ ] `pnpm dev` só sobe a API (worker e web não existem ainda).

## Linha do tempo

<!-- uma linha por sessão, mais recente no topo: AAAA-MM-DD | o que mudou | commit -->
2026-11-11 | proposta de SPEC-FASE-2 (aguarda aprovação) | ver `git log docs/proposta-spec-fase-2`
2026-11-11 | README.md do repositório | ver `git log feat/fase-1`
2026-11-11 | fase 1: Scope Guard, ScopedHttpClient, kill switch (vpn), scope-check, 10 testes de regressão | ver `git log feat/fase-1`
2026-11-11 | fase 0: monorepo, schema Prisma, API Nest, CLI `scan create`, 25 testes, compose | 74fdd50
2026-11-10 | ecossistema de contexto criado (CLAUDE.md, ESTADO, biblioteca, evidencias, comunicacao) | aeb3ce5
