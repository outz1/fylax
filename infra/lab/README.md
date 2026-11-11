# infra/lab: lab local de fixtures

Alvos de teste conhecidos para verificar o scanner sem tocar em nenhum alvo real. Rede Docker
**interna** `10.250.0.0/24` (sem rota para a internet).

| Container      | IP                    | O que expõe                                                                    | O que exercita                                                                                         |
| -------------- | --------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `lab-web`      | 10.250.0.10           | nginx 1.27 em HTTP puro (80)                                                   | `recon.http-cleartext`, `recon.server-banner`                                                          |
| `lab-tls`      | 10.250.0.11           | nginx em HTTPS (443), certificado autoassinado de 5 dias, CN `fixture.invalid` | `recon.tls-expired`, `recon.tls-hostname-mismatch`, certificado que não valida (TLS nunca é desligado) |
| `lab-ssh`      | 10.250.0.12           | OpenSSH (22), sem usuário                                                      | banner e versão                                                                                        |
| `lab-redis`    | 10.250.0.13           | Redis 7 (6379)                                                                 | `recon.exposed-service` (porta fora do top-1000 do nmap)                                               |
| `lab-gw`       | 10.250.0.2            | gateway com firewall em default DROP                                           | só deixa o worker local falar com o lab e com o Postgres e o Redis                                     |
| `worker-local` | (namespace do lab-gw) | consome a fila `scans-local`                                                   |                                                                                                        |

## Uso

```
pnpm lab:up      # sobe tudo (na primeira vez constrói as imagens)
pnpm scan -- create --target 10.250.0.13 --kind host --platform local
pnpm scan -- run <scanId>
pnpm lab:down    # derruba só o lab, nunca o Postgres
```

Scans com `--platform local` vão para a fila `scans-local`, atendida só pelo `worker-local`. Os de
`htb` e `thm` vão para `scans-lab` (worker no namespace do vpn). Cada worker recusa a plataforma do outro.

O certificado do `lab-tls` é descartável e vale 5 dias a partir do build: depois disso o finding passa
de "expira em menos de 14 dias" para "vencido". Reconstrua com `docker compose --profile lab build lab-tls`.
