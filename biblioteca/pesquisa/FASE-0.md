# FASE-0

Pergunta: que decisões a implementação da fase 0 tomou onde `docs/SPEC-FASE-1.md` é omissa?

## Decisões

D1 (2026-11-11): `apps/api` roda em CJS (sem `"type": "module"`) com `tsx`; decorators do Nest usam `@Inject(Classe)` explícito, porque esbuild (tsx e vitest) não emite `emitDecoratorMetadata`. Não usar injeção por tipo de parâmetro. | fonte: apps/api/src/*.service.ts
D2 (2026-11-11): `Finding` não tem coluna de módulo, então o filtro `?module=` de `GET /scans/:id/findings` usa a convenção `checkId = "<module>.<nome>"` (ex.: `web.xss`). Todo check novo deve seguir. | fonte: apps/api/src/scans.service.ts
D3 (2026-11-11): validação de entrada com Zod 4, compartilhada por REST e CLI (a regra vive no serviço, não no controller). Erros viram `DomainError` e o filtro global responde 400/404/409, nunca 500. | fonte: apps/api/src/schemas.ts, errors.ts
D4 (2026-11-11): `createScan` aceita `programId` opcional (extra à spec) porque `platform: bounty` exige um; programa inexistente retorna 404.
D5 (2026-11-11): `POST /programs` valida só a forma dos dados (a validação do brief e a revisão humana ficam para a fase 6) e rejeita `reviewedAt` futuro, que burlaria a regra de brief vencido da fase 1.
D6 (2026-11-11): API escuta só em `127.0.0.1` (sem autenticação nesta fase); Postgres e Redis publicam só em `127.0.0.1`.
D7 (2026-11-11): lint já barra `fetch`, `axios` e módulos `http/https/net/tls/dgram` fora de `packages/http` (antecipa um critério de aceite da fase 1). `scripts/check-no-emdash.mjs` aplica a regra do travessão ao código.

## Refutado

R1 (2026-11-11): `pnpm db:migrate -- --name init` trava. O `--` literal faz o Prisma tratar `--name init` como posicional e abrir prompt interativo. Uso correto: `pnpm db:migrate --name init`. Se travar, a sessão ociosa segura o advisory lock; encerre-a com `pg_terminate_backend`.

## Fontes

- docs/SPEC-FASE-1.md, seção "Fase 0"
