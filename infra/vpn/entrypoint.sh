#!/bin/sh
# Container "vpn": OpenVPN com kill switch por firewall.
#
# A ORDEM IMPORTA: o firewall fecha tudo (default DROP) ANTES de qualquer outra coisa.
# Saída permitida somente para:
#   - loopback;
#   - o endpoint do servidor VPN (IP, porta e protocolo do .ovpn), por qualquer interface;
#   - serviços internos listados em ALLOW_INTERNAL (postgres, redis);
#   - os CIDRs do lab, SOMENTE pela tun+ (rotas do .ovpn mais LAB_CIDRS).
# Se a tun0 cair, nada do lab sai e nada vaza pela rota padrão. Se algo estiver errado
# (sem .ovpn, sem CIDRs, config inválida) o container fica de pé com o firewall FECHADO.
#
# Os workers usam `network_mode: service:vpn` e herdam este namespace e estas regras.
set -eu

OVPN="${OVPN_FILE:-/vpn/lab.ovpn}"

log() { echo "[vpn] $*" >&2; }

# Erro de configuração: continua vivo, firewall fechado, sem tráfego.
fail_closed() {
  log "ERRO: $*"
  log "kill switch ativo: nada sai deste container até corrigir a configuração."
  exec tail -f /dev/null
}

mask_to_prefix() {
  p=0
  for o in $(echo "$1" | tr '.' ' '); do
    case "$o" in
      255) p=$((p + 8)) ;;
      254) p=$((p + 7)) ;;
      252) p=$((p + 6)) ;;
      248) p=$((p + 5)) ;;
      240) p=$((p + 4)) ;;
      224) p=$((p + 3)) ;;
      192) p=$((p + 2)) ;;
      128) p=$((p + 1)) ;;
      0) ;;
      *) return 1 ;;
    esac
  done
  echo "$p"
}

is_ipv4() { echo "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; }

# ---------------------------------------------------------------- 1. fecha tudo
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# IPv6: tudo fechado. Sem ip6tables só é aceitável se o IPv6 estiver desligado no namespace.
if ip6tables -F 2>/dev/null; then
  ip6tables -X
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
elif [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)" != "1" ]; then
  log "ERRO: sem ip6tables e com IPv6 ativo: não há como garantir o kill switch em IPv6."
  exit 1
fi
log "firewall fechado (default DROP em IPv4 e IPv6)"

# ---------------------------------------------------------------- 2. serviços internos
for item in $(echo "${ALLOW_INTERNAL:-}" | tr ',' ' '); do
  host="${item%%:*}"
  port="${item##*:}"
  is_ipv4 "$host" && echo "$port" | grep -Eq '^[0-9]{1,5}$' ||
    fail_closed "ALLOW_INTERNAL inválido: '$item' (use ip:porta)"
  iptables -A OUTPUT -p tcp -d "$host" --dport "$port" -j ACCEPT
  log "permitido: $host:$port/tcp (serviço interno)"
done

# ---------------------------------------------------------------- 3. configuração do lab
[ -f "$OVPN" ] || fail_closed "não encontrei $OVPN (coloque o .ovpn em infra/vpn/lab.ovpn)"

# 3a. endpoint(s) do servidor VPN
PROTO_DEFAULT="$(awk '$1=="proto"{print $2; exit}' "$OVPN" | tr -d '\r')"
norm_proto() {
  case "${1:-$PROTO_DEFAULT}" in
    udp*) echo udp ;;
    tcp*) echo tcp ;;
    '') echo udp ;;
    *) return 1 ;;
  esac
}

ENDPOINTS=0
while read -r host port proto; do
  [ -n "$host" ] || continue
  port="${port:-1194}"
  p="$(norm_proto "$proto")" || fail_closed "protocolo inválido no remote: $proto"
  echo "$port" | grep -Eq '^[0-9]{1,5}$' || fail_closed "porta inválida no remote: $port"
  if is_ipv4 "$host"; then
    ips="$host"
  else
    # O resolvedor embutido do Docker responde em loopback, que está liberado.
    ips="$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)"
  fi
  [ -n "$ips" ] || fail_closed "não consegui resolver o servidor VPN '$host' (apenas IPv4 é suportado)"
  for ip in $ips; do
    iptables -A OUTPUT -p "$p" -d "$ip" --dport "$port" -j ACCEPT
    log "permitido: servidor VPN $ip:$port/$p"
    ENDPOINTS=$((ENDPOINTS + 1))
  done
done <<EOF
$(awk '$1=="remote"{print $2, $3, $4}' "$OVPN" | tr -d '\r')
EOF
[ "$ENDPOINTS" -gt 0 ] || fail_closed "nenhuma linha 'remote' encontrada em $OVPN"

# 3b. CIDRs do lab: rotas do .ovpn + LAB_CIDRS (rotas empurradas pelo servidor não estão no arquivo)
ROUTE_CIDRS="$(awk '$1=="route" {print $2, $3}' "$OVPN" | tr -d '\r' | while read -r net mask; do
  is_ipv4 "$net" && is_ipv4 "$mask" || continue
  pre="$(mask_to_prefix "$mask")" || continue
  echo "$net/$pre"
done)"
ALL_CIDRS="$ROUTE_CIDRS $(echo "${LAB_CIDRS:-}" | tr ',' ' ')"

CIDRS=0
for c in $ALL_CIDRS; do
  echo "$c" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' || fail_closed "CIDR inválido: '$c'"
  [ "${c#*/}" -ge 8 ] || fail_closed "CIDR amplo demais: '$c' (prefixo mínimo /8)"
  iptables -A OUTPUT -o tun+ -d "$c" -j ACCEPT
  log "permitido: $c somente pela tun+"
  CIDRS=$((CIDRS + 1))
done
[ "$CIDRS" -gt 0 ] || fail_closed "nenhum CIDR do lab: defina LAB_CIDRS (ex.: 10.129.0.0/16) ou use 'route' no .ovpn"

# ---------------------------------------------------------------- 4. sobe a VPN
if [ "${FIREWALL_ONLY:-0}" = "1" ]; then
  log "FIREWALL_ONLY=1: firewall aplicado, OpenVPN NÃO iniciado (modo de teste)"
  exec tail -f /dev/null
fi

log "iniciando OpenVPN"
# Ignora o que o servidor tentar empurrar para mudar a rota padrão ou o DNS.
exec openvpn --config "$OVPN" \
  --pull-filter ignore "redirect-gateway" \
  --pull-filter ignore "dhcp-option" \
  --pull-filter ignore "block-outside-dns" \
  --script-security 1 \
  --verb 3
