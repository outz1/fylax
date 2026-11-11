# FASE-2B

Pergunta: que decisões a etapa 2b (recon com nmap travado, lab local de fixtures) tomou onde `PROPOSTA-SPEC-FASE-2.md` é omissa, e onde o teste real contradisse a proposta?

## Decisões

D1 (2026-11-11): **o perfil standard deixou de ser `--top-ports 100` e o deep deixou de ser `--top-ports 1000`** (desvio da tabela aprovada por Edu). Standard = portas 1 a 1024 + web alternativas (`ALT_WEB_PORTS`) + `SENSITIVE_PORTS` (1045 portas). Deep = todas as portas (1 a 65535). Motivo: ver R1. | fonte: packages/http/src/nmap-args.ts
D2 (2026-11-11): `SENSITIVE_PORTS` (porta para tipo de serviço) tem **dono único** em `@fylax/core`. O port scan garante que o standard as inclua e `recon.exposed-service` as usa para classificar; um teste de regressão confere que toda porta da lista está coberta pelo perfil.
D3 (2026-11-11): `--host-timeout` é **calculado**: `ceil(portas / taxa * 2) + 120 s`. Se passa de 3600 s o plano falha com erro explícito (ex.: deep a 5 req/s) antes de qualquer tráfego. O timeout do processo é esse valor mais 30 s. Antes era fixo (5 e 15 min).
D4 (2026-11-11): `Check.timeoutMs` opcional; o runner usa `check.timeoutMs ?? checkTimeoutMs ?? 60 s`. O `recon.port-scan` pede 70 min (teto do host-timeout mais folga).
D5 (2026-11-11): **modo "sem porta" no Scope Guard** (`portless`), só para o nmap. Um destino sem URL não prova a porta, então uma entrada de `inScope` com `ports` bloqueava o host inteiro. No modo portless: `inScope` casa ignorando portas e a regra devolve as portas permitidas (`rule.ports`); `outOfScope` com portas retira só essas portas (`excludedPorts`); sem portas retira o host. `urlPrefix` nunca autoriza port scan.
D6 (2026-11-11): o nmap recebe só os IPs validados, nunca o nome; `--exclude-ports` é a única flag extra permitida, e só quando o escopo exclui portas. `assertArgvSafe` reconfere o argv final (lista de flags proibidas e o script exato `banner,ssl-cert`).
D7 (2026-11-11): `tool.exec` é gravado em duas fases: `start` antes de executar (se falhar, o nmap não inicia) e `end` depois (código de saída, duração, portas abertas, erro truncado), sempre sem a saída bruta. O detalhe registra argv, IPs, perfil, taxa, número de portas e `hostTimeoutSec`.
D8 (2026-11-11): o nmap **nunca roda** em check passivo nem em scan passivo ou de programa com `automation: forbidden`: o processador entrega um `nmap` que recusa. Os checks de análise (tls-info, server-banner, exposed-service) só leem assets e por isso são `passive: true`.
D9 (2026-11-11): uma fila por ambiente de rede: `scans-lab` (HTB e THM, worker no `vpn`), `scans-local` (lab local, `worker-local` com firewall próprio) e `scans-bounty`. Cada worker só aceita a sua plataforma; o resto falha na hora. Evita que um scan caia num worker que alcança outra rede.
D10 (2026-11-11): lab local em `10.250.0.0/24`, rede Docker **interna** (sem saída para a internet): fixtures `lab-web` (nginx 1.27, HTTP puro), `lab-tls` (HTTPS autoassinado de 5 dias, CN que não cobre o host), `lab-ssh` (OpenSSH) e `lab-redis`. O `lab-gw` (mesma imagem do vpn, modo `LOCAL_LAB_CIDR`, sem OpenVPN) é o firewall do `worker-local`: default DROP, só o lab e o Postgres e o Redis. `pnpm lab:up` e `pnpm lab:down` (este derruba só o lab, nunca o Postgres).
D11 (2026-11-11): alvo `url` roda só o probe HTTP (`GET` e `HEAD`); o port scan só roda em alvo `host` (um escopo `urlPrefix` não autoriza varrer portas). Falha de transporte (certificado que não valida) vira dado (`error` no asset `url`), não falha do check; **a verificação TLS continua nunca sendo desligada**.
D12 (2026-11-11): findings do recon são `info` ou `low` e só comprovam. `recon.exposed-service` usa só a porta e o serviço que o nmap identificou; não envia comando de aplicação (D5 da proposta mantido).
D13 (2026-11-11): o `LAB_CIDRS` do `.env` é das redes de VPN (HTB e THM). O `worker-local` tem `LAB_CIDRS: 10.250.0.0/24` fixo no compose e não herda o do `.env`.

D14 (2026-11-11): **portão por check** no runner. `ctx.http`, `ctx.nmap` e `emitAsset` recusam qualquer chamada NOVA depois que o check foi cancelado, estourou o timeout ou terminou. Um check que ignora o `AbortSignal` (ou deixa um timer rodando) continua em segundo plano, mas não gera mais tráfego nem grava asset. O `nmap` também recebe o `signal` do check por padrão. Só o que já estava em andamento termina sozinho. Resolve o limite "check que ignora o AbortSignal" da 2a. | fonte: apps/worker/src/processor.ts `runCheck`
D15 (2026-11-11): **reaper de scans órfãos** (`apps/worker/src/reaper.ts`). Scan `running` cujo job não está mais vivo na fila (concluído, falho ou ausente, por worker morto ou Redis limpo) vira `failed` com motivo, e as tasks em andamento também. Job vivo (ativo, esperando, agendado) nunca é tocado: o BullMQ reentrega sozinho o job de um worker morto e o processador retoma. Roda 30 s depois de iniciar e a cada 5 min, com 2 min de graça, só para as plataformas da fila do worker. Resolve o limite "sem reaper" da 2a.
D16 (2026-11-11): **LF em todo o repositório** (`.gitattributes` com `* text=auto eol=lf` e `.editorconfig`). O `core.autocrlf=true` do Windows deixava a árvore de trabalho em CRLF, em desacordo com o Prettier, com os containers Linux e com o checksum das migrações do Prisma, e quebrou edições programáticas por padrão de texto. `docs/AGENT-GUIDE.md` e `docs/SPEC-FASE-1.md` (contratos de Edu) não foram tocados: o conteúdo no git já é LF e a árvore deles passa a LF no próximo checkout.
D17 (2026-11-11): **higiene dos testes**: nenhum teste deixa dado no Postgres (conferido: todas as tabelas em zero depois do `pnpm verify`) e os de fila limpam as três filas, também quando um worker real as consome.

## Refutado

R1 (2026-11-11): **`--top-ports 100` (standard) e `--top-ports 1000` (deep) da proposta aprovada.** O teste ponta a ponta contra o `lab-redis` voltou vazio. A porta 6379 estava aberta (conferida com nmap direto), mas no ranking de frequência do nmap 7.99 o Redis está na posição 2935, o MongoDB na 3071, o Memcached na 6388 e o Elasticsearch (9200) na 733. Nenhum dos dois perfis os alcançava, e `recon.exposed-service` ficaria cego justamente para esses serviços. Solução: D1 e D2.
R2 (2026-11-11): `--host-timeout` fixo de 5 min. Com a taxa baixa que o escopo pode impor (1 req/s sem política de automação), o nmap abandona o host e devolve vazio, um falso negativo silencioso. Solução: D3.
R3 (2026-11-11): timeout padrão de 60 s por check para o port scan. O scan do TLS levou 34 s com 4 portas explícitas e o standard completo leva 20 a 55 s por host. Solução: D4.
R4 (2026-11-11): o parser XML (fast-xml-parser) aceita XML truncado e devolvia "nenhum host", ou seja, nmap morto no meio virava "nenhuma porta aberta". Solução: `XMLValidator` antes de interpretar; teste com a saída real cortada em 5 pontos.
R5 (2026-11-11): usar `String.replace` do JavaScript para editar script shell: a sequência `$'` no texto novo é um padrão especial e inseriu o resto do arquivo. Corrigido restaurando o arquivo do git. Para edições programáticas, usar `split(...).join(...)` ou a ferramenta de edição.
R6 (2026-11-11): conferir só a contagem `Tests` do vitest. Dois arquivos com erro de sintaxe não compilaram e a contagem (17) parecia apenas menor. Conferir sempre `Test Files` junto.
R7 (2026-11-11): o teste do pacote `db` gravava um `scope.block` sem `scanId` e nunca o apagava: cada `pnpm verify` deixava uma linha no banco de desenvolvimento (6 acumuladas). Corrigido com um marcador por execução.
R8 (2026-11-11): o teste de fila assumia que ninguém consome `scans-local` e olhava só os jobs "esperando". Com o lab de pé o `worker-local` consome o job na hora e o teste falhava. Agora olha o job em qualquer estado.
R9 (2026-11-11): `String.replace` do JavaScript também interpreta `$&`, `$1` e `$'` no texto novo, e as edições com `
` não casam em arquivo CRLF. As duas causas já tinham derrubado edições: normalizar o fim de linha na leitura e usar `split(...).join(...)`.

## Limites conhecidos

- A detecção de versão do nmap envia sondas de protocolo (por exemplo `GET /` ou um ClientHello), além de ler o banner. É prática padrão de reconhecimento e não é exploração, mas vai além do que o D5 da proposta descrevia. **Confirmado por Edu em 2026-11-11.** Enviar comandos de aplicação por conta própria (ex.: `PING` no Redis) continua fora.
- O deep (65535 portas) leva cerca de 11 min por host a 100 req/s e é recusado quando o escopo impõe taxa baixa. Para programa, o deep só serve com portas explícitas ou escopo com taxa alta.
- O nmap só roda no worker de lab (`worker-lab` no vpn e `worker-local`). O worker de bounty precisa do próprio firewall de saída antes de rodar nmap (fase 6).
- O teste de integração com nmap real (`lab.integration.test.ts`) pula quando o lab não está de pé: rode `pnpm lab:up` antes de `pnpm verify` para exercitá-lo.
- Os fixtures XML (`packages/http/src/__fixtures__`) são da versão 7.99 do nmap; uma versão futura pode mudar o formato do `ssl-cert`.
- O TLS do `lab-tls` é descartável (5 dias, sem chave reaproveitada); depois de 5 dias o `recon.tls-expired` passa de "expira" para "vencido".

## Fontes

- biblioteca/pesquisa/PROPOSTA-SPEC-FASE-2.md, etapa 2b
- teste ponta a ponta de 2026-11-11 contra `infra/lab` (4 fixtures)
