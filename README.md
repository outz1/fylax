# fylax (vulnscan)

Scanner que **detecta e comprova** vulnerabilidades, sem armar, para estudo em labs (Hack The Box, TryHackMe, lab local) e para programas de bug bounty autorizados.

Um check identifica a falha, coleta a evidência mínima de reprodução e para. O projeto não tem exploits de execução remota, payloads armados, brute force, negação de serviço nem exfiltração, e não terá.

## Status

| Fase | Conteúdo | Situação |
| --- | --- | --- |
| 0 | Fundação: monorepo, banco, tipos do núcleo, CLI que cria um scan | concluída |
| 1 | Escopo e rede: Scope Guard, `ScopedHttpClient`, VPN com kill switch | concluída |
| 2a | Orquestração: worker, fila, ciclo de vida, runner de checks, confirmação humana | em revisão (PR) |
| 2b | Recon com nmap travado e lab local de fixtures | implementada, em revisão |
| 3 a 7 | Web, API, MCP, relatório e bounty, harness | não iniciadas |
| GUI | Interface Next.js (versão mínima logo após a 2b) | spec a escrever |

O que existe hoje: criar, enfileirar, confirmar, cancelar e consultar scans (CLI e REST), workers que executam o scan atrás de um firewall, cadastro de programas, decisão de escopo (`scope-check`), o cliente HTTP que só fala com o que o Scope Guard permite e o **módulo de recon**: port scan e detecção de serviço com nmap travado, sondagem HTTP, leitura de certificado TLS e findings informativos (versão exposta, HTTP sem HTTPS, certificado vencido ou que não cobre o host, banco ou cache acessível). **Ainda não há checks de vulnerabilidade web, de API nem de MCP.**

## Princípios

1. **Só detectar e comprovar, nunca armar.**
2. **Nada roda fora do escopo.** Todo tráfego passa pelo Scope Guard e pelo `ScopedHttpClient`, a única API de rede do projeto, e o nmap só roda pelo `ScopedNmap` (argv de lista fechada, só IPs validados, auditado). Há um teste automático e uma regra de lint contra `fetch`, `axios`, `http`, `net` e execução do nmap fora de `packages/http`.
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
# criar um scan (fica queued) e enfileirar para o worker de lab
pnpm scan -- create --target 10.250.0.10 --kind host --platform local
pnpm scan -- run <scanId>

# programa com automação não especificada espera confirmação humana antes de ir para a fila
pnpm scan -- confirm <scanId>
pnpm scan -- cancel <scanId>

# simular a decisão de escopo, sem enviar tráfego HTTP
pnpm scan -- scope-check https://api.exemplo.com --program exemplo
pnpm scan -- scope-check 10.129.0.10 --lab-cidr 10.129.0.0/16
pnpm scan -- scope-check 10.129.0.10 --ovpn infra/vpn/lab.ovpn

# lab local de fixtures (10.250.0.0/24, rede interna): alvos de teste conhecidos, sem tocar em nada real
pnpm lab:up
pnpm scan -- create --target 10.250.0.13 --kind host --platform local
pnpm scan -- run <scanId>      # scans do lab local vão para a fila scans-local (worker-local)
pnpm lab:down                  # derruba só o lab, nunca o Postgres

# scans de HTB e THM rodam no worker do compose, dentro do namespace do vpn (kill switch)
docker compose --profile worker up -d --build

# desenvolvimento: API em http://127.0.0.1:3001 (só localhost, sem autenticação) e worker na máquina
pnpm dev
```

`scope-check` sai com código 0 se o destino é permitido e 1 se é bloqueado. `run` sai com 3 quando o scan aguarda confirmação. A API expõe `POST /scans`, `GET /scans`, `GET /scans/:id`, `GET /scans/:id/findings`, `POST /scans/:id/run|confirm|cancel` e `POST|GET /programs`.

> **Atenção:** o worker do `pnpm dev` roda na sua máquina e **não tem kill switch de rede**. Ele serve para desenvolver. Use o `worker-lab` do compose para qualquer scan real.

## Configuração

Tudo vem do `.env` (veja `.env.example`). As variáveis que importam para o escopo:

| Variável | Para que serve |
| --- | --- |
| `LAB_CIDRS` | Redes das VPNs de lab (ex.: `10.129.0.0/16` no HTB). Somadas às linhas `route` do `.ovpn`. Sem nenhuma, o worker da VPN recusa o scan. O lab local tem a própria rede (`10.250.0.0/24`) fixa no compose. |
| `FYLAX_LAN_CIDRS` | Faixas extras da sua LAN, bloqueio absoluto. Já cobertos por padrão: `192.168.0.0/16` e `172.16.0.0/12`. |

Segredos (`.env`, `*.ovpn`, `programs/*.local.yaml`) nunca entram no git.

## Estrutura

```
apps/api            API NestJS, Prisma, CLI (create, run, confirm, cancel, scope-check)
apps/worker         worker BullMQ: executa scans, roda os checks por módulo (imagem em apps/worker/Dockerfile, com nmap)
packages/core       tipos e contratos do núcleo
packages/scope      Scope Guard: resolver de escopo, contexto de scan, auditoria, validação
packages/http       ScopedHttpClient e ScopedNmap: únicas formas de falar com a rede
packages/checks     checks de vulnerabilidade, por módulo (hoje: recon)
packages/queue      filas BullMQ (enfileiramento compartilhado por API e CLI)
packages/db         sinks de audit e de asset no Postgres, carga do .env
infra/              docker compose (postgres, redis, vpn) e container vpn com kill switch
infra/lab           fixtures do lab local (web, tls, ssh, redis) em 10.250.0.0/24
docs/               contrato do agente e especificações das fases
biblioteca/         decisões, método e catálogo de dados do projeto
ESTADO.md           onde estamos, próxima ação e pendências
```

## Desenvolvimento

- Stack: monorepo pnpm, TypeScript estrito, NestJS, Prisma, PostgreSQL, Redis, Vitest.
- `pnpm verify` é a porta de qualidade (lint, typecheck e testes). Os testes de kill switch usam Docker e são pulados sem ele; o teste de integração com nmap real (`lab.integration.test.ts`) só roda com o lab de pé (`pnpm lab:up` antes).
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
