# Fixture: HTTPS com certificado autoassinado, nome que não cobre o host e validade curta (5 dias),
# o que exercita recon.tls-expired e recon.tls-hostname-mismatch. Nada aqui é segredo: o certificado
# é descartável e só existe dentro do lab.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/certs \
 && openssl req -x509 -nodes -newkey rsa:2048 -days 5 \
      -subj "/CN=fixture.invalid/O=Fylax Lab" \
      -addext "subjectAltName=DNS:fixture.invalid" \
      -keyout /etc/nginx/certs/key.pem -out /etc/nginx/certs/cert.pem \
 && apk del openssl
COPY default.conf /etc/nginx/conf.d/default.conf
