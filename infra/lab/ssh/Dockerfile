# Fixture: servidor SSH (só o banner e a versão importam). Sem usuário e sem senha: ninguém loga.
FROM alpine:3.20
RUN apk add --no-cache openssh-server && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
