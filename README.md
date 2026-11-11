# fylax (vulnscan)

Scanner que **detecta e comprova** vulnerabilidades, sem armar, para estudo em labs (Hack The Box, TryHackMe, lab local) e para programas de bug bounty autorizados.

Um check identifica a falha, coleta a evidência mínima de reprodução e para. O projeto não tem exploits de execução remota, payloads armados, brute force, negação de serviço nem exfiltração, e não terá.

## Status

| Fase | Conteúdo | Situação |
| --- | --- | --- |
| 0 | Fundação: monorepo, banco, tipos do núcleo, CLI que cria um scan | concluída |
| 1 | Escopo e rede: Scope Guard, `ScopedHttpClient`, VPN com kill switch | implementada, em revisão |
| 2 a 7 | Recon, web, API, MCP, relatório, bounty, harness | não iniciadas |

O que existe hoje: criar e consultar scans (CLI e REST), cadastrar programas, decidir se um destino está no escopo (`scope-check`) e o cliente HTTP que só fala com o que o Scope Guard permite. Ainda não há checks de vulnerabilidade nem workers.

## Princípios

1. **Só detectar e comprovar, nunca armar.**
2. **Nada roda fora do escopo.** Todo tráfego passa pelo Scope Guard e pelo `ScopedHttpClient`, a única API de rede do projeto. Há um teste automático e uma regra de lint contra `fetch`, `axios`, `http` e `net` fora de `packages/http`.
3. **Nada destrutivo.** Sem DoS, brute force ou teste de carga.
4. **Autorização é humana.** O agente nunca decide que um alvo é autorizado: isso vem de um lab na allowlist ou de um programa cadastrado e revisado.
5. **Em dúvida, pare e pergunte.**

O contrato completo está em [`docs/AGENT-GUIDE.md`](docs/AGENT-GUIDE.md).

## Como o escopo é protegido

Duas camadas independentes:

- **Scope Guard** (`packages/scope`): resolve o DNS e decide allow ou block antes de cada request. Bloqueia sempre, em qualquer modo: loopback, link-local, metadados de cloud (`169.254.169.254`) e a sua LAN. Em modo lab, o IP precisa cair na allowlist do `.ovpn`. Em modo programa, vale `outOfScope` primeiro, depois a política de automação, a validade da revisão do brief, a cadeia de CNAME e, por fim, `inScope`. Toda decisão vai para o `AuditLog`.
- **Rede** (`infra/vpn`): container OpenVPN com firewall em default DROP. Se a `tun0` cair, nada sai e nada vaza pela rota padrão.

O `ScopedHttpClient` fixa na conexão o IP que o Scope Guard validou (anula DNS rebinding), revalida cada redirect, aplica rate limit e nunca desliga a verificação TLS.

## Requisitos

- Node `>=20.18.1` (desenvolvido em Node 24)
- pnpm 10 (`corepack enable`)
- Docker com Compose (WSL2 no Windows)

## Primeiros passos

```bash
pnpm install
cp .env.example .env        # troque a senha e mantenha DATABASE_URL coerente com ela
docker compose up -d        # postgres, redis e vpn
pnpm db:migrate             # aplica as migrações
pnpm verify                 # lint, typecheck e testes
```

O serviço `vpn` sobe fechado e não saudável enquanto não existir `infra/vpn/lab.ovpn`. É o comportamento esperado. Veja [`infra/vpn/README.md`](infra/vpn/README.md) para ligar um lab.

## Uso

```bash
# criar um scan (fica com status queued; ainda não há worker)
pnpm scan -- create --target 10.129.0.10 --kind host --platform htb

# simular a decisão de escopo, sem enviar tráfego HTTP
pnpm scan -- scope-check https://api.exemplo.com --program exemplo
pnpm scan -- scope-check 10.129.0.10 --lab-cidr 10.129.0.0/16
pnpm scan -- scope-check 10.129.0.10 --ovpn infra/vpn/lab.ovpn

# API REST em http://127.0.0.1:3001 (só localhost, sem autenticação nesta fase)
pnpm dev
```

`scope-check` sai com código 0 se o destino é permitido e 1 se é bloqueado. A API expõe `POST /scans`, `GET /scans`, `GET /scans/:id`, `GET /scans/:id/findings` e `POST|GET /programs`.

## Configuração

Tudo vem do `.env` (veja `.env.example`). As variáveis que importam para o escopo:

| Variável | Para que serve |
| --- | --- |
| `LAB_CIDRS` | Redes do lab (ex.: `10.129.0.0/16` no HTB). Somadas às linhas `route` do `.ovpn`. |
| `FYLAX_LAN_CIDRS` | Faixas extras da sua LAN, bloqueio absoluto. Já cobertos por padrão: `192.168.0.0/16` e `172.16.0.0/12`. |

Segredos (`.env`, `*.ovpn`, `programs/*.local.yaml`) nunca entram no git.

## Estrutura

```
apps/api            API NestJS, Prisma, CLI (scan create, scope-check)
packages/core       tipos e contratos do núcleo
packages/scope      Scope Guard: resolver de escopo, auditoria, validação
packages/http       ScopedHttpClient: única API de rede do projeto
infra/              docker compose (postgres, redis, vpn) e container vpn com kill switch
docs/               contrato do agente e especificações das fases
biblioteca/         decisões, método e catálogo de dados do projeto
ESTADO.md           onde estamos, próxima ação e pendências
```

## Desenvolvimento

- Stack: monorepo pnpm, TypeScript estrito, NestJS, Prisma, PostgreSQL, Redis, Vitest.
- `pnpm verify` é a porta de qualidade (lint, typecheck e testes). O teste do kill switch usa Docker e é pulado se o Docker não estiver disponível.
- Commits seguem Conventional Commits, com uma fase por branch e um PR por fase.
- Todo check e todo guard de escopo têm teste.
- Mudanças em `packages/scope`, `packages/http` e `infra/vpn` exigem revisão humana.

## Documentação

- [`docs/AGENT-GUIDE.md`](docs/AGENT-GUIDE.md): contrato de trabalho, limites e checkpoints de revisão.
- [`docs/SPEC-FASE-1.md`](docs/SPEC-FASE-1.md): especificação executável das fases 0 e 1.
- [`biblioteca/pesquisa/`](biblioteca/pesquisa/): decisões de implementação, uma por fase.
- [`ESTADO.md`](ESTADO.md): estado atual do projeto.

## Uso responsável

Use só contra alvos que você tem autorização para testar: labs que são seus ou da plataforma (HTB, THM) e programas de bug bounty cujo escopo você leu e cadastrou. Relatórios de bounty são sempre enviados manualmente.
