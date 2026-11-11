# Worker de lab. Roda no namespace de rede do container `vpn` (network_mode: service:vpn),
# então herda o firewall e o kill switch. Contexto de build: a raiz do repositório.
FROM node:24-alpine

# openssl: engine do Prisma em musl. nmap e nmap-scripts: port scan e scripts banner e ssl-cert (2b).
RUN apk add --no-cache openssl libc6-compat nmap nmap-scripts && corepack enable

WORKDIR /app
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY apps ./apps
COPY packages ./packages

# Workspace inteiro: o postinstall de apps/api roda `prisma generate` (o schema mora lá) e o client
# gerado é o mesmo que o worker usa.
RUN pnpm install --frozen-lockfile

ENV NODE_ENV=production FYLAX_WORKER_IN_VPN=1
USER node
WORKDIR /app/apps/worker
# exec: o tsx recebe SIGTERM e encerra o worker com calma.
CMD ["sh", "-c", "exec ./node_modules/.bin/tsx src/main.ts"]
