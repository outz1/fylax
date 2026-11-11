import { XMLParser, XMLValidator } from 'fast-xml-parser';
import type { NmapHost, NmapPort, NmapServiceInfo, TlsInfo } from '@fylax/core';

export class NmapParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NmapParseError';
  }
}

const ARRAYS = new Set(['host', 'address', 'port', 'script', 'elem', 'table', 'cpe']);
const MAX_BANNER = 300;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseTagValue: false,
  parseAttributeValue: false,
  processEntities: true,
  isArray: (name) => ARRAYS.has(name),
});

type Node = Record<string, unknown>;

const asNode = (v: unknown): Node | undefined =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Node) : undefined;
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);
const attr = (n: Node | undefined, name: string): string | undefined => {
  const v = n?.[`@_${name}`];
  return typeof v === 'string' ? v : undefined;
};
const text = (v: unknown): string | undefined => {
  if (typeof v === 'string') return v;
  const n = asNode(v);
  const t = n?.['#text'];
  return typeof t === 'string' ? t : undefined;
};

/** Mapa chave para valor dos `<elem key="...">` diretos de uma tabela. */
function elemMap(table: Node | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of asArray(table?.elem)) {
    const key = attr(asNode(e), 'key');
    const value = text(e);
    if (key && value !== undefined) out[key] = value;
  }
  return out;
}

function subTable(table: Node | undefined, key: string): Node | undefined {
  return asArray(table?.table)
    .map(asNode)
    .find((t) => attr(t, 'key') === key);
}

function joinDn(map: Record<string, string>): string {
  return Object.entries(map)
    .map(([k, v]) => `${k}=${v}`)
    .join('/');
}

/** Interpreta o resultado do script ssl-cert (formato estruturado do nmap). */
function parseSslCert(script: Node): TlsInfo | undefined {
  const subject = elemMap(subTable(script, 'subject'));
  const issuer = elemMap(subTable(script, 'issuer'));
  const validity = elemMap(subTable(script, 'validity'));
  if (!validity.notAfter || !validity.notBefore) return undefined;

  const san: string[] = [];
  const extensions = subTable(script, 'extensions');
  for (const ext of asArray(extensions?.table).map(asNode)) {
    const map = elemMap(ext);
    if (/subject alternative name/i.test(map.name ?? '') && map.value) {
      for (const part of map.value.split(',')) {
        const name = part
          .trim()
          .replace(/^(DNS|IP Address|IP):/i, '')
          .trim();
        if (name) san.push(name);
      }
    }
  }
  return {
    subject: joinDn(subject),
    issuer: joinDn(issuer),
    san,
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
  };
}

function parsePort(p: Node): NmapPort | undefined {
  const state = asNode(p.state);
  if (attr(state, 'state') !== 'open') return undefined;
  const portid = Number(attr(p, 'portid'));
  const protocol = attr(p, 'protocol');
  if (!Number.isInteger(portid) || portid < 1 || portid > 65535 || protocol !== 'tcp')
    return undefined;

  const result: NmapPort = {
    port: portid,
    protocol: 'tcp',
    state: 'open',
    reason: attr(state, 'reason') ?? '',
  };

  const svc = asNode(p.service);
  const service: NmapServiceInfo = {
    cpe: asArray(svc?.cpe)
      .map(text)
      .filter((c): c is string => !!c),
  };
  if (svc) {
    const name = attr(svc, 'name');
    const product = attr(svc, 'product');
    const version = attr(svc, 'version');
    const extra = attr(svc, 'extrainfo');
    if (name) service.name = name;
    if (product) service.product = product;
    if (version) service.version = version;
    if (extra) service.extraInfo = extra;
    if (attr(svc, 'tunnel') === 'ssl') service.tunnel = 'ssl';
  }

  for (const s of asArray(p.script).map(asNode)) {
    if (!s) continue;
    const id = attr(s, 'id');
    if (id === 'banner') {
      const out = attr(s, 'output')?.trim();
      if (out) service.banner = out.slice(0, MAX_BANNER);
    } else if (id === 'ssl-cert') {
      const tls = parseSslCert(s);
      if (tls) result.tls = tls;
    }
  }

  if (svc || service.banner) result.service = service;
  return result;
}

/** Converte o XML do nmap (`-oX -`) em hosts e portas abertas. Entrada inválida vira NmapParseError. */
export function parseNmapXml(xml: string): NmapHost[] {
  // O parser sozinho aceita XML truncado e devolveria "nenhuma porta": um falso negativo silencioso.
  // Saída cortada (timeout, limite de bytes, processo morto) precisa virar erro.
  const valid = XMLValidator.validate(xml);
  if (valid !== true) {
    throw new NmapParseError(`XML do nmap inválido ou truncado: ${valid.err.msg}`);
  }
  let doc: Node | undefined;
  try {
    doc = asNode(parser.parse(xml));
  } catch (e) {
    throw new NmapParseError(`XML do nmap inválido: ${e instanceof Error ? e.message : String(e)}`);
  }
  // <nmaprun/> vazio (nenhum host) é resposta válida; a ausência do elemento não é.
  if (!doc || !('nmaprun' in doc)) throw new NmapParseError('XML do nmap sem <nmaprun>');
  const run = asNode(doc.nmaprun) ?? {};

  const hosts: NmapHost[] = [];
  for (const h of asArray(run.host).map(asNode)) {
    if (!h) continue;
    const addr = asArray(h.address)
      .map(asNode)
      .find((a) => attr(a, 'addrtype') === 'ipv4' || attr(a, 'addrtype') === 'ipv6');
    const ip = attr(addr, 'addr');
    if (!ip) continue;
    const ports = asArray(asNode(h.ports)?.port)
      .map(asNode)
      .map((p) => (p ? parsePort(p) : undefined))
      .filter((p): p is NmapPort => p !== undefined);
    hosts.push({ ip, ports });
  }
  return hosts;
}
