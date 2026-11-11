import { describe, expect, it } from 'vitest';
import { ValidationFailedError } from './errors';
import { createProgramSchema, createScanSchema, parse } from './schemas';

const scanValido = { targetKind: 'host', targetValue: '10.129.0.10', platform: 'htb' };

describe('createScanSchema', () => {
  it('aceita entrada válida e aplica profile padrão', () => {
    expect(parse(createScanSchema, scanValido)).toMatchObject({ profile: 'standard' });
  });

  it('rejeita kind inválido com erro de validação', () => {
    expect(() => parse(createScanSchema, { ...scanValido, targetKind: 'ftp' })).toThrow(
      ValidationFailedError,
    );
  });

  it('rejeita platform e profile inválidos', () => {
    expect(() => parse(createScanSchema, { ...scanValido, platform: 'xyz' })).toThrow(
      ValidationFailedError,
    );
    expect(() => parse(createScanSchema, { ...scanValido, profile: 'agressivo' })).toThrow(
      ValidationFailedError,
    );
  });

  it('rejeita alvo vazio ou ausente', () => {
    expect(() => parse(createScanSchema, { ...scanValido, targetValue: '   ' })).toThrow(
      ValidationFailedError,
    );
    expect(() => parse(createScanSchema, undefined)).toThrow(ValidationFailedError);
  });

  it('rejeita platform bounty sem programId', () => {
    const erro = (() => {
      try {
        parse(createScanSchema, { ...scanValido, platform: 'bounty' });
      } catch (e) {
        return e;
      }
    })();
    expect(erro).toBeInstanceOf(ValidationFailedError);
    expect((erro as ValidationFailedError).issues[0]?.path).toBe('programId');
  });

  it('aceita platform bounty com programId', () => {
    const programId = '3f8a6c1e-5b0a-4c8e-9d52-1a2b3c4d5e6f';
    expect(parse(createScanSchema, { ...scanValido, platform: 'bounty', programId })).toMatchObject(
      { programId },
    );
  });
});

describe('createProgramSchema', () => {
  const base = {
    platform: 'hackerone',
    name: 'exemplo',
    briefUrl: 'https://hackerone.com/exemplo',
    inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
    rules: {
      automation: 'allowed',
      maxRequestsPerSecond: 5,
      testAccountsOnly: true,
      forbidden: ['dos'],
    },
    reviewedAt: new Date().toISOString(),
  };

  it('aceita programa válido', () => {
    expect(parse(createProgramSchema, base).outOfScope).toEqual([]);
  });

  it('rejeita inScope vazio', () => {
    expect(() => parse(createProgramSchema, { ...base, inScope: [] })).toThrow(
      ValidationFailedError,
    );
  });

  it('rejeita reviewedAt no futuro', () => {
    const futuro = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    expect(() => parse(createProgramSchema, { ...base, reviewedAt: futuro })).toThrow(
      ValidationFailedError,
    );
  });

  it('rejeita escopo amplo demais (wildcard de TLD, CIDR da internet, URL sem http)', () => {
    for (const entrada of [
      { kind: 'wildcard', value: '*.com' },
      { kind: 'cidr', value: '0.0.0.0/0' },
      { kind: 'urlPrefix', value: 'ftp://exemplo.com/*' },
    ]) {
      expect(() => parse(createProgramSchema, { ...base, inScope: [entrada] })).toThrow(
        ValidationFailedError,
      );
      expect(() => parse(createProgramSchema, { ...base, outOfScope: [entrada] })).toThrow(
        ValidationFailedError,
      );
    }
  });

  it('rejeita automation inválido', () => {
    expect(() =>
      parse(createProgramSchema, { ...base, rules: { ...base.rules, automation: 'sim' } }),
    ).toThrow(ValidationFailedError);
  });
});
