import { describe, expect, it } from 'vitest';
import type { AuditSink } from '@fylax/core';
import { ScopeGuard } from './guard';
import { ScopeViolationError } from './errors';
import { ScopeResolver } from './resolver';
import { FakeDns, MemoryAudit, NOW, programCtx } from './testing';
import { parseOvpnRoutes } from './ovpn';
import { redactUrl } from './redact';
import { validateCidr, validateScopeEntry } from './validate';

const dns = new FakeDns({ 'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } });
const resolver = new ScopeResolver({ dns, now: () => NOW });

describe('ScopeGuard', () => {
  it('grava scope.allow e scope.block no audit, com motivo e regra', async () => {
    const audit = new MemoryAudit();
    const guard = new ScopeGuard(resolver, audit);
    await guard.check('https://api.exemplo.com/x?token=segredo', programCtx({}), { scanId: 's1' });
    await guard.check('http://127.0.0.1/', programCtx({}), { scanId: 's1' });

    expect(audit.actions()).toEqual(['scope.allow', 'scope.block']);
    const [allow, block] = audit.entries;
    expect(allow?.scanId).toBe('s1');
    expect(allow?.detail).toMatchObject({
      host: 'api.exemplo.com',
      mode: 'program',
      program: 'exemplo',
      rule: { kind: 'wildcard', value: '*.exemplo.com' },
    });
    expect(block?.detail).toMatchObject({ host: '127.0.0.1' });
    expect(String(block?.detail.reason)).toMatch(/bloqueio absoluto/);
  });

  it('o valor da query nunca vai para o audit', async () => {
    const audit = new MemoryAudit();
    await new ScopeGuard(resolver, audit).check(
      'https://api.exemplo.com/x?token=segredo&a=1',
      programCtx({}),
    );
    expect(JSON.stringify(audit.entries)).not.toContain('segredo');
  });

  it('assertAllowed lança ScopeViolationError quando bloqueado', async () => {
    const guard = new ScopeGuard(resolver, new MemoryAudit());
    await expect(guard.assertAllowed('http://127.0.0.1/', programCtx({}))).rejects.toBeInstanceOf(
      ScopeViolationError,
    );
    await expect(
      guard.assertAllowed('https://api.exemplo.com', programCtx({})),
    ).resolves.toMatchObject({
      allowed: true,
    });
  });

  it('fail closed: se o audit falha, o erro sobe', async () => {
    const quebrado: AuditSink = {
      record: async () => {
        throw new Error('banco fora');
      },
    };
    await expect(
      new ScopeGuard(resolver, quebrado).check('https://api.exemplo.com', programCtx({})),
    ).rejects.toThrow('banco fora');
  });
});

describe('utilitários de escopo', () => {
  it('parseOvpnRoutes extrai CIDRs das linhas route', () => {
    const ovpn = [
      'client',
      'remote vpn.example.net 1337 udp',
      'route 10.129.0.0 255.255.0.0',
      '  route 10.10.10.0 255.255.255.0 vpn_gateway',
      '# route 1.2.3.0 255.255.255.0',
      'route-nopull',
      'route 10.0.0.0 255.0.255.0',
      'route 10.129.0.0 255.255.0.0',
    ].join('\r\n');
    expect(parseOvpnRoutes(ovpn)).toEqual(['10.129.0.0/16', '10.10.10.0/24']);
  });

  it('validateCidr recusa CIDR inválido ou amplo demais', () => {
    expect(validateCidr('10.129.0.0/16')).toBeNull();
    expect(validateCidr('10.0.0.0/8')).toBeNull();
    expect(validateCidr('0.0.0.0/0')).toMatch(/amplo demais/);
    expect(validateCidr('8.0.0.0/7')).toMatch(/amplo demais/);
    expect(validateCidr('::/0')).toMatch(/amplo demais/);
    expect(validateCidr('lixo')).toMatch(/inválido/);
    expect(validateCidr('10.0.0.0/33')).toMatch(/inválido/);
  });

  it('validateScopeEntry recusa wildcard amplo e URL sem http(s)', () => {
    expect(validateScopeEntry({ kind: 'wildcard', value: '*.exemplo.com' })).toBeNull();
    expect(validateScopeEntry({ kind: 'wildcard', value: '*.com' })).toMatch(/wildcard inválido/);
    expect(validateScopeEntry({ kind: 'wildcard', value: '*' })).toMatch(/wildcard inválido/);
    expect(validateScopeEntry({ kind: 'host', value: 'api.exemplo.com' })).toBeNull();
    expect(validateScopeEntry({ kind: 'host', value: 'api.exemplo.com/x' })).toMatch(
      /host inválido/,
    );
    expect(validateScopeEntry({ kind: 'urlPrefix', value: 'https://ex.com/api/*' })).toBeNull();
    expect(validateScopeEntry({ kind: 'urlPrefix', value: 'ftp://ex.com/*' })).toMatch(/http/);
    expect(validateScopeEntry({ kind: 'cidr', value: '0.0.0.0/0' })).toMatch(/amplo demais/);
  });

  it('redactUrl mantém nomes de parâmetros e descarta valores, credenciais e fragmento', () => {
    expect(redactUrl('https://u:p@ex.com:8443/a/b?token=x&token=y&q=1#frag')).toBe(
      'https://ex.com:8443/a/b?token=…&q=…',
    );
    expect(redactUrl('nao-e-url')).toBe('(url inválida)');
  });
});
