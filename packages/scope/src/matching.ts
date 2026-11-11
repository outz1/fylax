import type { ScopeEntry } from '@fylax/core';
import type { Destination } from './destination';
import { normalizeHost } from './destination';
import { inCidr, parseCidr, type ParsedIp } from './net';

export interface Target {
  dest: Destination;
  ips: ParsedIp[];
}

function portOk(entry: ScopeEntry, port: number | undefined): boolean {
  if (!entry.ports || entry.ports.length === 0) return true;
  return port !== undefined && entry.ports.includes(port);
}

/** "*.ex.com" casa a.ex.com e a.b.ex.com, mas não ex.com nem evil-ex.com. */
export function wildcardMatches(pattern: string, host: string): boolean {
  const p = normalizeHost(pattern);
  if (!p.startsWith('*.')) return false;
  const suffix = p.slice(1); // ".ex.com"
  return host.length > suffix.length && host.endsWith(suffix);
}

function nameEntryMatches(entry: ScopeEntry, host: string): boolean {
  if (entry.kind === 'host') return normalizeHost(entry.value) === host;
  if (entry.kind === 'wildcard') return wildcardMatches(entry.value, host);
  return false;
}

/** Só nomes de host (host e wildcard), ignorando porta: usado na cadeia de CNAME. */
export function nameInList(entries: readonly ScopeEntry[], host: string): ScopeEntry | undefined {
  return entries.find((e) => nameEntryMatches(e, host));
}

function urlPrefixMatches(entry: ScopeEntry, dest: Destination): boolean {
  if (!dest.url) return false;
  let base: URL;
  try {
    base = new URL(entry.value.replace(/\*+$/, ''));
  } catch {
    return false;
  }
  const effective = (u: URL) => (u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80);
  if (base.protocol !== dest.url.protocol) return false;
  if (normalizeHost(base.hostname) !== dest.host) return false;
  if (effective(base) !== effective(dest.url)) return false;
  const basePath = base.pathname.replace(/\/+$/, '');
  const destPath = dest.url.pathname.replace(/\/+$/, '');
  return destPath === basePath || destPath.startsWith(`${basePath}/`);
}

/**
 * Entrada de escopo (inScope): para CIDR, TODOS os IPs resolvidos precisam estar dentro.
 */
export function matchesInScope(entry: ScopeEntry, target: Target): boolean {
  if (!portOk(entry, target.dest.port)) return false;
  switch (entry.kind) {
    case 'host':
    case 'wildcard':
      return nameEntryMatches(entry, target.dest.host);
    case 'urlPrefix':
      return urlPrefixMatches(entry, target.dest);
    case 'cidr': {
      const cidr = parseCidr(entry.value);
      return cidr !== null && target.ips.length > 0 && target.ips.every((ip) => inCidr(ip, cidr));
    }
  }
}

/**
 * Entrada de exclusão (outOfScope): basta UM IP, o nome do host ou um nome da cadeia de CNAME casar.
 * Fora de escopo sempre vence.
 */
export function matchesOutOfScope(
  entry: ScopeEntry,
  target: Target,
  cnames: readonly string[],
): boolean {
  if (!portOk(entry, target.dest.port)) return false;
  switch (entry.kind) {
    case 'host':
    case 'wildcard':
      return [target.dest.host, ...cnames].some((name) => nameEntryMatches(entry, name));
    case 'urlPrefix':
      return urlPrefixMatches(entry, target.dest);
    case 'cidr': {
      const cidr = parseCidr(entry.value);
      return cidr !== null && target.ips.some((ip) => inCidr(ip, cidr));
    }
  }
}
