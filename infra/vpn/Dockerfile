FROM alpine:3.20

RUN apk add --no-cache openvpn iptables ip6tables iproute2

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Saudável só com a tun0 de pé e com endereço. Sem isso, o worker não tem rede (kill switch).
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
  CMD ip -4 addr show dev tun0 | grep -q inet || exit 1

ENTRYPOINT ["/entrypoint.sh"]
