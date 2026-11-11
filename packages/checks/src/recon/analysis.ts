import { SENSITIVE_PORTS, type Asset, type Check, type Finding, type TlsInfo } from '@fylax/core';
import { clean, finding, hostPort, isPortService, num, str } from '../util';

const DAY_MS = 24 * 60 * 60 * 1000;
export const TLS_EXPIRY_WARNING_DAYS = 14;

/** O nmap devolve datas em UTC sem fuso ("2026-11-06T10:00:00"). */
function parseNmapDate(value: string): Date | undefined {
  const d = new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(value) ? value : `${value}Z`);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

/** SAN "*.ex.com" cobre um rótulo (a.ex.com), nunca ex.com nem a.b.ex.com. */
function nameMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === h) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1);
    return (
      h.endsWith(suffix) &&
      !h.slice(0, h.length - suffix.length).includes('.') &&
      h.length > suffix.length
    );
  }
  return false;
}

function commonName(subject: string): string | undefined {
  return /(?:^|\/)commonName=([^/]+)/.exec(subject)?.[1];
}

export function certificateCoversHost(tls: TlsInfo, host: string): boolean {
  const names =
    tls.san.length > 0 ? tls.san : [commonName(tls.subject)].filter((n): n is string => !!n);
  return names.some((n) => nameMatches(n, host));
}

const tlsOf = (a: Asset): TlsInfo | undefined =>
  isPortService(a) && a.data.tls && typeof a.data.tls === 'object'
    ? (a.data.tls as TlsInfo)
    : undefined;

/** Só analisa assets já descobertos: não gera tráfego, por isso é passivo. */
export function createTlsInfo(now: () => Date): Check {
  return {
    id: 'recon.tls-info',
    module: 'recon',
    severity: 'low',
    references: [],
    passive: true,
    appliesTo: (a) => tlsOf(a) !== undefined,
    async run(ctx) {
      const findings: Finding[] = [];
      for (const svc of ctx.assets) {
        const tls = tlsOf(svc);
        const host = str(svc.data.host);
        const port = num(svc.data.port);
        if (!tls || !host || port === undefined) continue;
        const where = hostPort(host, port);
        const cert = {
          subject: tls.subject,
          issuer: tls.issuer,
          san: tls.san,
          notBefore: tls.notBefore,
          notAfter: tls.notAfter,
        };

        const notAfter = parseNmapDate(tls.notAfter);
        if (notAfter) {
          const msLeft = notAfter.getTime() - now().getTime();
          if (msLeft < TLS_EXPIRY_WARNING_DAYS * DAY_MS) {
            const expired = msLeft < 0;
            const days = Math.floor(Math.abs(msLeft) / DAY_MS);
            findings.push(
              finding({
                checkId: 'recon.tls-expired',
                title: expired
                  ? `Certificado TLS vencido (${where})`
                  : `Certificado TLS expira em menos de ${TLS_EXPIRY_WARNING_DAYS} dias (${where})`,
                severity: 'low',
                confidence: 'high',
                asset: where,
                description: expired
                  ? `O certificado apresentado venceu há ${days} dia(s). Clientes recusam a conexão ou treinam usuários a ignorar o aviso.`
                  : `O certificado vence em ${days} dia(s). Sem renovação, o serviço fica inacessível para clientes que validam o certificado.`,
                evidence: {
                  notAfter: tls.notAfter,
                  ...(expired ? { expiredDaysAgo: days } : { daysLeft: days }),
                  cert,
                },
                reproduction: [
                  `Abrir uma conexão TLS em ${where}`,
                  'Ler o certificado do servidor',
                  'Comparar o campo notAfter com a data atual',
                ],
                references: ['https://cwe.mitre.org/data/definitions/298.html'],
                dedupKey: `recon.tls-expired:${where}`,
              }),
            );
          }
        }

        if (!certificateCoversHost(tls, host)) {
          findings.push(
            finding({
              checkId: 'recon.tls-hostname-mismatch',
              title: `Certificado TLS não cobre o host (${where})`,
              severity: 'low',
              confidence: 'high',
              asset: where,
              description: `Nenhum nome do certificado (SAN ou CN) corresponde a ${host}. Clientes que validam o nome rejeitam a conexão.`,
              evidence: { host, cert },
              reproduction: [
                `Abrir uma conexão TLS em ${where}`,
                'Ler os nomes do certificado (SAN e CN)',
                `Conferir que nenhum cobre ${host}`,
              ],
              references: ['https://cwe.mitre.org/data/definitions/297.html'],
              dedupKey: `recon.tls-hostname-mismatch:${where}`,
            }),
          );
        }
      }
      return findings;
    },
  };
}

const VERSIONED = /\d+(\.\d+)+/;

/** Produto e versão identificados (nmap ou cabeçalhos Server e X-Powered-By). */
export const serverBanner: Check = {
  id: 'recon.server-banner',
  module: 'recon',
  severity: 'info',
  references: [],
  passive: true,
  appliesTo: (a) =>
    (isPortService(a) && !!str(a.data.product) && !!str(a.data.version)) ||
    (a.type === 'url' && (!!str(a.data.server) || !!str(a.data.poweredBy))),
  async run(ctx) {
    const findings: Finding[] = [];
    const covered = new Set<string>();

    for (const svc of ctx.assets.filter(isPortService)) {
      const product = str(svc.data.product);
      const version = str(svc.data.version);
      const host = str(svc.data.host);
      const port = num(svc.data.port);
      if (!product || !version || !host || port === undefined) continue;
      covered.add(`${host}:${port}`);
      const where = hostPort(host, port);
      findings.push(
        finding({
          checkId: 'recon.server-banner',
          title: `Versão de serviço exposta: ${product} ${version} (${where})`,
          severity: 'info',
          confidence: 'high',
          asset: where,
          description: `O serviço revela produto e versão (${product} ${version}). Isso facilita buscar vulnerabilidades conhecidas dessa versão.`,
          evidence: clean({
            product,
            version,
            name: str(svc.data.name),
            cpe: svc.data.cpe,
            banner: str(svc.data.banner),
          }),
          reproduction: [
            `Conectar em ${where}`,
            'Ler o banner ou a resposta de identificação do serviço',
          ],
          references: ['https://cwe.mitre.org/data/definitions/200.html'],
          dedupKey: `recon.server-banner:svc:${where}`,
        }),
      );
    }

    for (const u of ctx.assets.filter((a) => a.type === 'url')) {
      const url = str(u.data.url);
      if (!url) continue;
      let host: string;
      let port: number;
      try {
        const parsed = new URL(url);
        host = parsed.hostname;
        port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
      } catch {
        continue;
      }
      // O nmap já reportou essa porta com versão: não repete pelo cabeçalho.
      if (covered.has(`${host}:${port}`)) continue;

      for (const [field, header] of [
        ['server', 'Server'],
        ['poweredBy', 'X-Powered-By'],
      ] as const) {
        const value = str(u.data[field]);
        if (!value || !VERSIONED.test(value)) continue;
        findings.push(
          finding({
            checkId: 'recon.server-banner',
            title: `Versão exposta no cabeçalho ${header}: ${value} (${hostPort(host, port)})`,
            severity: 'info',
            confidence: 'high',
            asset: hostPort(host, port),
            description: `O cabeçalho ${header} revela produto e versão (${value}).`,
            evidence: { url, header, value },
            reproduction: [`GET ${url}`, `Ler o cabeçalho ${header} da resposta`],
            references: ['https://cwe.mitre.org/data/definitions/200.html'],
            dedupKey: `recon.server-banner:http:${hostPort(host, port)}:${field}`,
          }),
        );
      }
    }
    return findings;
  },
};

const SENSITIVE_NAMES: Record<string, string> = {
  mysql: 'banco de dados',
  mariadb: 'banco de dados',
  postgresql: 'banco de dados',
  redis: 'banco de dados',
  mongodb: 'banco de dados',
  memcached: 'cache',
  memcache: 'cache',
  'ms-sql-s': 'banco de dados',
  'oracle-tns': 'banco de dados',
  cassandra: 'banco de dados',
  couchdb: 'banco de dados',
  telnet: 'administração remota',
  vnc: 'administração remota',
  'ms-wbt-server': 'administração remota (RDP)',
  docker: 'administração de containers',
};

/** Porta de banco, cache ou administração aberta. Só pela porta e pelo serviço detectado, sem enviar nada. */
export const exposedService: Check = {
  id: 'recon.exposed-service',
  module: 'recon',
  severity: 'info',
  references: [],
  passive: true,
  appliesTo: (a) => a.type === 'port' || isPortService(a),
  async run(ctx) {
    const findings: Finding[] = [];
    const reported = new Set<string>();

    const report = (
      host: string,
      ip: string | undefined,
      port: number,
      kind: string,
      svc: Asset | undefined,
      byName: boolean,
    ) => {
      const where = hostPort(host, port);
      if (reported.has(where)) return;
      reported.add(where);
      const name = str(svc?.data.name);
      findings.push(
        finding({
          checkId: 'recon.exposed-service',
          title: `Serviço sensível acessível: ${name ?? `porta ${port}`} (${where})`,
          severity: 'info',
          confidence: byName ? 'high' : 'medium',
          asset: where,
          description: `Há um serviço de ${kind} acessível em ${where}. Serviços desse tipo normalmente não devem estar expostos a quem não precisa deles.`,
          evidence: clean({
            host,
            ip,
            port,
            service: name,
            product: str(svc?.data.product),
            version: str(svc?.data.version),
            detectedBy: byName ? 'serviço' : 'porta',
          }),
          reproduction: [
            `Abrir uma conexão TCP em ${where}`,
            'Conferir que a porta aceita a conexão (sem enviar dados)',
          ],
          references: ['https://cwe.mitre.org/data/definitions/668.html'],
          dedupKey: `recon.exposed-service:${where}`,
        }),
      );
    };

    for (const svc of ctx.assets.filter(isPortService)) {
      const host = str(svc.data.host);
      const port = num(svc.data.port);
      if (!host || port === undefined) continue;
      const byName = SENSITIVE_NAMES[str(svc.data.name) ?? ''];
      const byPort = SENSITIVE_PORTS[port];
      if (byName) report(host, str(svc.data.ip), port, byName, svc, true);
      else if (byPort) report(host, str(svc.data.ip), port, byPort, svc, false);
    }
    for (const p of ctx.assets.filter((a) => a.type === 'port')) {
      const host = str(p.data.host);
      const port = num(p.data.port);
      const kind = port !== undefined ? SENSITIVE_PORTS[port] : undefined;
      if (host && port !== undefined && kind)
        report(host, str(p.data.ip), port, kind, undefined, false);
    }
    return findings;
  },
};
