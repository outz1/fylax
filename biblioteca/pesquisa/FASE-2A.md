# FASE-2A

Pergunta: que decisões a etapa 2a (orquestração: worker, ciclo de vida, runner, confirmação) tomou onde `PROPOSTA-SPEC-FASE-2.md` é omissa?

## Decisões

D1 (2026-11-11): fila por plataforma: `htb`, `thm` e `local` vão para `scans-lab`; `bounty` vai para `scans-bounty`. `jobId = scanId`, então enfileirar duas vezes não duplica a execução; `attempts: 1`. | fonte: packages/core `queueForPlatform`, packages/queue
D2 (2026-11-11): scan `bounty` pode ser enfileirado, mas **não há consumidor** de `scans-bounty` até a fase 6 (ele fica `queued`). O worker de lab recusa job de outra plataforma (`failed`: "não é atendida pela fila"), como segunda barreira. | fonte: apps/worker/src/processor.ts
D3 (2026-11-11): confirmação humana só para programa com `automation: unspecified` (`needsConfirmation`). `run` não enfileira sem `confirmedAt`; `confirm` grava `confirmedAt`, audita `scan.confirm` e enfileira (idempotente: não regrava nem duplica o audit). O worker confere de novo e falha fechado (`confirmação humana ausente`) se chegar um job sem confirmação.
D4 (2026-11-11): além de `Scan.confirmedAt` (pedido de Edu), a migração `scan_lifecycle` adiciona `Scan.error` (motivo de falha do scan, que não tinha onde ficar) e `Asset.dedupKey` com `@@unique([scanId, dedupKey])` (reprocessar não duplica asset). Ações de audit novas: `scan.confirm` e `scan.cancel`.
D5 (2026-11-11): o alvo entra como asset de partida **só em memória**, para o `appliesTo` dos checks ter onde casar: alvo `host` vira `service`; os demais viram `url`. Não é persistido (não polui a contagem de assets).
D6 (2026-11-11): perfil `passive`, ou programa com `automation: forbidden`, roda **só** checks com `passive: true`, e todo request desses checks sai com `passive: true` (o Scope Guard já trata o resto).
D7 (2026-11-11): cancelamento: a API muda para `canceled` com `updateMany` condicional (`queued` ou `running`); o worker confere o status no banco **antes de cada check** (determinístico) e também a cada 1 s (poll) para interromper o check em curso via `AbortSignal`. O worker só conclui um scan que ainda esteja `running`: nunca sobrescreve um cancelamento.
D8 (2026-11-11): timeout por check (padrão 60 s) e isolamento de erro: o check que falha ou estoura vira `Task.error` e os demais seguem; o scan termina `done` (a falha fica visível na task). `checkId` do finding precisa começar com `<módulo>.` do check; fora disso é rejeitado e vira erro da task.
D9 (2026-11-11): entrega pelo menos uma vez: o scan é reivindicado por `updateMany` atômico (`queued` para `running`). Só um job **reentregue** (`attemptsStarted > 1`, worker caiu no meio) retoma um scan `running`; a execução é idempotente por `dedupKey` (finding e asset) e incrementa `Task.attempts`.
D10 (2026-11-11): worker de lab roda em imagem própria (`apps/worker/Dockerfile`, Alpine, instalação do workspace inteiro) e entra no compose como `worker-lab` (perfil `worker`) com `network_mode: service:vpn`: herda firewall e kill switch. Alcança só Postgres e Redis (`ALLOW_INTERNAL`) e o lab. Se o `vpn` reiniciar, reinicie o `worker-lab` junto.
D11 (2026-11-11): `pnpm dev` roda API e worker **na máquina**, sem kill switch; o worker avisa no log quando `FYLAX_WORKER_IN_VPN` não é `1`. Scans reais só pelo `worker-lab`.
D12 (2026-11-11): novos pacotes: `@fylax/db` (sinks Prisma de audit e de asset, `loadEnv`) e `@fylax/queue` (BullMQ). `@fylax/scope` absorveu os schemas de escopo e `resolveScanContext` para API e worker validarem igual. `@fylax/core` ganhou `emitAsset`, `signal` e `passive` no contrato do check.
D13 (2026-11-11): lab local de fixtures em `10.250.0.0/24` (Edu). Entra na allowlist por `LAB_CIDRS`; o `infra/lab` em si é da 2b.

## Refutado

R1 (2026-11-11): `pnpm install --filter "@fylax/worker..."` no Dockerfile. O Prisma procura o próprio pacote a partir da pasta do schema (`apps/api`), que a instalação filtrada não instala, e tenta um auto-install que falha. Solução: instalar o workspace inteiro; o `postinstall` da API gera o client.
R2 (2026-11-11): `prisma migrate dev` em ambiente não interativo com aviso de constraint única. Pede confirmação e aborta. Solução: gerar o SQL com `prisma migrate diff --from-schema-datasource ... --script`, conferir, gravar em `migrations/<ts>_<nome>/migration.sql` e aplicar com `migrate deploy`.
R3 (2026-11-11): regex `http.request(` do teste de rede pegava `ctx.http.request(` (o `ScopedHttpClient`, uso correto). Agora só pega o `http.request(` solto (módulo do Node); `require('net')` e afins também são cobertos, porque a regra de lint só olha `import`.
R4 (2026-11-11): o teste de cancelamento só cobria o check em curso. A mutação "remover a guarda entre checks" sobreviveu, e sem a guarda o corpo do próximo check chegava a começar. Corrigido com a leitura direta do status e o teste `14b`.

## Limites conhecidos

- O registro de checks está **vazio**: a 2a entrega a orquestração; os primeiros checks reais (recon) vêm na 2b. Por isso um scan de lab termina `done` com `tasks: 0`.
- ~~Um check que ignora o `AbortSignal` é abandonado, mas pode continuar executando em segundo plano.~~ Mitigado na 2b (D14): ele continua existindo, mas não consegue mais gerar tráfego nem gravar asset.
- ~~Não há "reaper".~~ Resolvido na 2b (D15).
- O `msgpackr-extract` (acelerador nativo opcional do BullMQ) fica bloqueado pelo pnpm; a biblioteca usa JavaScript puro.
- `scans-bounty` não tem worker (fase 6); `run` de scan bounty enfileira e o scan fica `queued`.

## Fontes

- biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md, etapa 2a
