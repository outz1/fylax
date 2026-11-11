# infra/vpn: OpenVPN com kill switch

Container usado por todos os workers de lab (`network_mode: "service:vpn"`).

## Uso

1. Copie o `.ovpn` do lab para `infra/vpn/lab.ovpn` (gitignored e fora do contexto do build).
2. No `.env`, defina `LAB_CIDRS` com as redes do lab (ex.: `10.129.0.0/16` para HTB). Rotas que o
   servidor empurra não aparecem no arquivo; as linhas `route` do `.ovpn` são somadas.
3. `docker compose up -d` (o serviço `vpn` sobe junto). Saudável = `tun0` de pé.

## Firewall (default DROP, IPv4 e IPv6)

Saída permitida só para: loopback; IP, porta e protocolo do servidor VPN; `ALLOW_INTERNAL`
(postgres e redis); `LAB_CIDRS` e rotas do `.ovpn`, **somente pela `tun+`**.

Sem `tun0`, nada do lab sai e nada vaza pela rota padrão. Configuração inválida (sem `.ovpn`,
sem CIDRs, CIDR amplo demais) deixa o container de pé com o firewall **fechado**.

## O mesmo escopo nas duas camadas

A allowlist do Scope Guard (`packages/scope`) e a do firewall devem ser as mesmas: derive as duas do
`.ovpn` e de `LAB_CIDRS`.

## Testar à mão

```
docker compose --profile probe run --rm net-probe wget -q -T 5 -O- http://10.129.0.10/
```

O teste automatizado do kill switch está em `packages/http/src/killswitch.smoke.test.ts`.
