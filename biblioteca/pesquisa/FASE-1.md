# FASE-1

Pergunta: que decisões a implementação do Scope Guard, do ScopedHttpClient e do kill switch tomou onde `docs/SPEC-FASE-1.md` é omissa?

## Decisões

D1 (2026-11-11): bloqueio absoluto = loopback, 0.0.0.0/8, link-local e metadados de cloud (169.254.0.0/16, 100.100.100.200, 192.0.0.192), multicast, reservado, IPv6 (::1, fe80::/10, fc00::/7, ff00::/8, NAT64, 6to4) e a LAN privada **192.168.0.0/16 e 172.16.0.0/12**, mais `FYLAX_LAN_CIDRS`. O `10.0.0.0/8` NÃO é bloqueado por padrão porque HTB e THM usam 10.x. IPv4 embutido em IPv6 é desembrulhado antes de checar. | fonte: packages/scope/src/net.ts
D2 (2026-11-11): todos os IPs resolvidos precisam passar. Um IP ruim entre vários bloqueia o destino. Em `inScope` do tipo `cidr`, todos os IPs precisam estar dentro; em `outOfScope`, basta um.
D3 (2026-11-11): `*.ex.com` casa `a.ex.com` e `a.b.ex.com`, nunca `ex.com` nem `evil-ex.com`. Quem quer o apex lista o host. Wildcard de TLD (`*.com`) é recusado no cadastro.
D4 (2026-11-11): CNAME de terceiro: todo nome da cadeia de CNAME precisa estar em `inScope` (host ou wildcard); IP de terceiro sem CNAME passa normalmente.
D5 (2026-11-11): entradas amplas demais são recusadas no cadastro e na allowlist do lab: CIDR com prefixo menor que /8 (IPv4) ou /32 (IPv6), wildcard sem dois rótulos, urlPrefix sem http(s). Entrada inválida em runtime nunca casa (fail closed).
D6 (2026-11-11): `urlPrefix` casa esquema, host, porta efetiva e fronteira de caminho (`/api` casa `/api` e `/api/x`, não `/apix`); `..` e `%2e%2e` são normalizados pelo parser de URL antes da comparação. Destino sem esquema não casa `urlPrefix`. Entrada com `ports` exige porta conhecida; destino sem esquema nem porta não prova a porta (block).
D7 (2026-11-11): URL com credenciais embutidas (`user@host`) e esquema diferente de http(s) são bloqueados.
D8 (2026-11-11): `automation: unspecified` limita a 1 req/s (`UNSPECIFIED_MAX_RPS`) e marca `requiresConfirmation`. Teto por perfil: passive 1, standard 5, deep 10, bounty 2; vale o menor entre perfil e escopo.
D9 (2026-11-11): o IP validado pelo Scope Guard é **fixado** na conexão (`connect.lookup` do undici), o que anula DNS rebinding entre a checagem e o connect. O SNI e a verificação de certificado continuam usando o nome do host. O DNS é revalidado a cada tentativa e a cada hop de redirect.
D10 (2026-11-11): redirects: o transporte nunca segue; o cliente revalida cada `Location`. Só GET e HEAD são seguidos (limite 5). Redirect bloqueado, de método não seguível ou acima do limite vira asset `url` (query redigida) e a resposta 3xx volta com `redirect.followed = false`. `Authorization`, `Cookie` e `Proxy-Authorization` caem ao trocar de origem.
D11 (2026-11-11): AuditLog nunca guarda valor de query, valor de header nem corpo (`redactUrl` mantém só os nomes dos parâmetros). Fail closed: se o audit falhar, o erro sobe e nenhum request sai.
D12 (2026-11-11): retry só para GET, HEAD e OPTIONS, só em falha de transporte retentável (timeout, reset, ECONNREFUSED, EHOSTUNREACH), backoff 500 ms e dobrando, 2 tentativas extras. Erro de certificado nunca é retentado nem contornado.
D13 (2026-11-11): firewall do `vpn`: default DROP em IPv4 e IPv6 aplicado ANTES de qualquer outra coisa. Saída só para loopback, IP:porta:protocolo do servidor VPN, `ALLOW_INTERNAL` (postgres 172.31.250.10:5432 e redis 172.31.250.11:6379) e os CIDRs do lab **somente pela `tun+`**. Configuração inválida deixa o container de pé com o firewall fechado. Rede fixa `172.31.250.0/24`.
D14 (2026-11-11): allowlist do lab = rotas `route` do `.ovpn` + `LAB_CIDRS`. Rotas empurradas pelo servidor não estão no arquivo, então `LAB_CIDRS` é obrigatório se o `.ovpn` não tiver `route`. As duas camadas (Scope Guard e firewall) leem a mesma fonte.
D15 (2026-11-11): `.gitattributes` força LF em `*.sh` e Dockerfile (CRLF quebra o entrypoint no Linux); `.dockerignore` mantém `*.ovpn` fora do contexto do build.

## Refutado

R1 (2026-11-11): usar `httpd` do busybox no teste do kill switch. O Alpine não o traz (fica em `busybox-extras`); o servidor de teste usa um loop com `nc`.
R2 (2026-11-11): `docker logs` repassa o stderr do container no stderr de quem chamou. Ler só stdout deixa a asserção de log sempre falsa.

## Limites conhecidos

- O OpenVPN real (túnel de pé, `tun0` com endereço) NÃO foi testado: não há `.ovpn` na máquina. O smoke test cobre o firewall com `FIREWALL_ONLY=1` (aplica as regras e não inicia o OpenVPN) e o caso sem `tun0`.
- Lab com certificado autoassinado vai falhar no `ScopedHttpClient`: a verificação TLS nunca é desligada. Se for um problema, a saída é confiar na CA do lab explicitamente (decisão de Edu).
- A rede 172.16.0.0/12 bloqueada inclui a bridge padrão do Docker: um lab local em container (`platform: local`) em 172.x será bloqueado até Edu decidir a faixa dele.

## Fontes

- docs/SPEC-FASE-1.md, seção "Fase 1"
