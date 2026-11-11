import ipaddr from 'ipaddr.js';

export type ParsedIp = ipaddr.IPv4 | ipaddr.IPv6;
export type ParsedCidr = [ParsedIp, number];

/** Aceita só IPv4 decimal pontuado e IPv6 sem zone id. Formas ambíguas (hex, octal, inteiro) são recusadas. */
export function parseIp(raw: string): ParsedIp | null {
  const s = raw.trim().replace(/^\[|\]$/g, '');
  try {
    if (s.includes(':')) {
      if (s.includes('%') || !ipaddr.IPv6.isValid(s)) return null;
      return normalizeIp(ipaddr.IPv6.parse(s));
    }
    if (!ipaddr.IPv4.isValidFourPartDecimal(s)) return null;
    return ipaddr.IPv4.parse(s);
  } catch {
    return null;
  }
}

/** IPv4 embutido em IPv6 (::ffff:a.b.c.d) vira IPv4, para não escapar das regras de bloqueio. */
export function normalizeIp(ip: ParsedIp): ParsedIp {
  if (ip.kind() === 'ipv6' && (ip as ipaddr.IPv6).isIPv4MappedAddress()) {
    return (ip as ipaddr.IPv6).toIPv4Address();
  }
  return ip;
}

/** CIDR válido; um IP sem máscara vale como /32 (ou /128). */
export function parseCidr(raw: string): ParsedCidr | null {
  const value = raw.trim();
  try {
    const withMask = value.includes('/') ? value : `${value}/${value.includes(':') ? 128 : 32}`;
    const [addr, bits] = withMask.split('/') as [string, string];
    const base = parseIp(addr);
    if (!base || !/^\d{1,3}$/.test(bits)) return null;
    const n = Number(bits);
    const max = base.kind() === 'ipv4' ? 32 : 128;
    if (n < 0 || n > max) return null;
    return [base, n];
  } catch {
    return null;
  }
}

export function inCidr(ip: ParsedIp, cidr: ParsedCidr): boolean {
  const [base, bits] = cidr;
  if (ip.kind() !== base.kind()) return false;
  return (ip as ipaddr.IPv4).match([base as ipaddr.IPv4, bits]);
}

export function ipToString(ip: ParsedIp): string {
  return ip.toString();
}

interface BlockedRange {
  cidr: string;
  label: string;
}

/**
 * Bloqueio absoluto: vale em qualquer modo e nenhuma allowlist ou escopo libera.
 * A LAN do operador entra aqui: o padrão cobre as faixas privadas que NÃO são usadas por
 * HTB/THM (que usam 10.0.0.0/8). Faixas extras vêm de FYLAX_LAN_CIDRS.
 */
export const ABSOLUTE_BLOCKS: readonly BlockedRange[] = [
  { cidr: '0.0.0.0/8', label: 'rede "esta máquina" (0.0.0.0/8)' },
  { cidr: '127.0.0.0/8', label: 'loopback (127.0.0.0/8)' },
  { cidr: '169.254.0.0/16', label: 'link-local e metadados de cloud (169.254.0.0/16)' },
  { cidr: '100.100.100.200/32', label: 'metadados de cloud (100.100.100.200)' },
  { cidr: '192.0.0.192/32', label: 'metadados de cloud (192.0.0.192)' },
  { cidr: '192.168.0.0/16', label: 'LAN privada (192.168.0.0/16)' },
  { cidr: '172.16.0.0/12', label: 'LAN privada (172.16.0.0/12)' },
  { cidr: '224.0.0.0/4', label: 'multicast (224.0.0.0/4)' },
  { cidr: '240.0.0.0/4', label: 'reservado e broadcast (240.0.0.0/4)' },
  { cidr: '::/128', label: 'endereço não especificado (::)' },
  { cidr: '::1/128', label: 'loopback (::1)' },
  { cidr: '::/96', label: 'IPv4 compatível (::/96)' },
  { cidr: 'fe80::/10', label: 'link-local (fe80::/10)' },
  { cidr: 'fc00::/7', label: 'LAN privada e metadados de cloud (fc00::/7)' },
  { cidr: 'ff00::/8', label: 'multicast (ff00::/8)' },
  { cidr: '64:ff9b::/96', label: 'NAT64 (pode embutir IPv4 bloqueado)' },
  { cidr: '2002::/16', label: '6to4 (pode embutir IPv4 bloqueado)' },
];

const PARSED_BLOCKS = ABSOLUTE_BLOCKS.map((b) => ({
  ...b,
  parsed: parseCidr(b.cidr) as ParsedCidr,
}));

export interface BlockHit {
  cidr: string;
  label: string;
}

export function absoluteBlock(
  ip: ParsedIp,
  extraLanCidrs: readonly string[] = [],
): BlockHit | null {
  for (const b of PARSED_BLOCKS) {
    if (inCidr(ip, b.parsed)) return { cidr: b.cidr, label: b.label };
  }
  for (const cidr of extraLanCidrs) {
    const parsed = parseCidr(cidr);
    if (parsed && inCidr(ip, parsed)) return { cidr, label: `LAN configurada (${cidr})` };
  }
  return null;
}
