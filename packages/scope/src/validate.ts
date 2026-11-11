import type { ScopeEntry } from '@fylax/core';
import { parseCidr, parseIp } from './net';

const MIN_V4_PREFIX = 8;
const MIN_V6_PREFIX = 32;

/** CIDR utilizável como escopo ou allowlist: válido e não amplo a ponto de abranger a internet. */
export function validateCidr(value: string): string | null {
  const cidr = parseCidr(value);
  if (!cidr) return `CIDR inválido: ${value}`;
  const [base, bits] = cidr;
  const min = base.kind() === 'ipv4' ? MIN_V4_PREFIX : MIN_V6_PREFIX;
  if (bits < min) return `CIDR amplo demais (${value}): prefixo mínimo /${min}`;
  return null;
}

/** Retorna a mensagem de erro, ou null se a entrada é aceitável. */
export function validateScopeEntry(entry: ScopeEntry): string | null {
  const v = entry.value.trim();
  switch (entry.kind) {
    case 'cidr':
      return validateCidr(v);
    case 'wildcard':
      return /^\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)
        ? null
        : `wildcard inválido: "${v}" (use *.dominio.tld, com ao menos dois rótulos após o *)`;
    case 'host': {
      if (parseIp(v)) return null;
      try {
        const host = new URL(`http://${v}`).hostname;
        return host === v.toLowerCase() ? null : `host inválido: "${v}"`;
      } catch {
        return `host inválido: "${v}"`;
      }
    }
    case 'urlPrefix': {
      try {
        const u = new URL(v.replace(/\*+$/, ''));
        if (u.protocol !== 'http:' && u.protocol !== 'https:')
          return `urlPrefix precisa de http(s): "${v}"`;
        if (u.username || u.password) return 'urlPrefix não pode ter credenciais';
        return null;
      } catch {
        return `urlPrefix inválido: "${v}"`;
      }
    }
  }
}
