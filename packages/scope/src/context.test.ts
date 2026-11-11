import { describe, expect, it } from 'vitest';
import {
  ScopeContextError,
  needsConfirmation,
  parseProgramScope,
  resolveScanContext,
  type ProgramRow,
} from './context';
import { daysAgo } from './testing';

const semArquivo = () => undefined;

function programa(over: Partial<ProgramRow> = {}): ProgramRow {
  return {
    name: 'exemplo',
    inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
    outOfScope: [],
    rules: {
      automation: 'allowed',
      maxRequestsPerSecond: 5,
      testAccountsOnly: false,
      forbidden: [],
    },
    reviewedAt: daysAgo(1),
    ...over,
  };
}

describe('resolveScanContext', () => {
  it('lab: allowlist = rotas do .ovpn + LAB_CIDRS, sem duplicar', () => {
    const ctx = resolveScanContext(
      { platform: 'htb' },
      { OVPN_FILE: '/vpn/lab.ovpn', LAB_CIDRS: '10.10.10.0/24, 10.129.0.0/16' },
      () => 'remote x 1337\nroute 10.129.0.0 255.255.0.0\n',
    );
    expect(ctx).toEqual({ mode: 'lab', allowlist: ['10.129.0.0/16', '10.10.10.0/24'] });
  });

  it('thm e local também usam a allowlist de lab', () => {
    for (const platform of ['thm', 'local'] as const) {
      const ctx = resolveScanContext({ platform }, { LAB_CIDRS: '10.250.0.0/24' }, semArquivo);
      expect(ctx).toEqual({ mode: 'lab', allowlist: ['10.250.0.0/24'] });
    }
  });

  it('lab sem allowlist falha (nenhum request pode sair)', () => {
    expect(() => resolveScanContext({ platform: 'htb' }, {}, semArquivo)).toThrow(
      ScopeContextError,
    );
    expect(() =>
      resolveScanContext({ platform: 'htb' }, { OVPN_FILE: '/x.ovpn' }, () => 'remote x 1\n'),
    ).toThrow(/sem allowlist de lab/);
  });

  it('lab com CIDR amplo demais falha', () => {
    expect(() =>
      resolveScanContext({ platform: 'htb' }, { LAB_CIDRS: '0.0.0.0/0' }, semArquivo),
    ).toThrow(/amplo demais/);
  });

  it('bounty exige programa e valida o JSON do banco', () => {
    expect(() => resolveScanContext({ platform: 'bounty' }, {}, semArquivo)).toThrow(
      /sem programa/,
    );
    const ctx = resolveScanContext({ platform: 'bounty', program: programa() }, {}, semArquivo);
    expect(ctx.mode).toBe('program');
    expect(() =>
      resolveScanContext(
        {
          platform: 'bounty',
          program: programa({ inScope: [{ kind: 'cidr', value: '0.0.0.0/0' }] }),
        },
        {},
        semArquivo,
      ),
    ).toThrow(ScopeContextError);
    expect(() => parseProgramScope(programa({ rules: { automation: 'talvez' } }))).toThrow(
      /escopo inválido/,
    );
  });

  it('o programa de um scan de lab é ignorado', () => {
    const ctx = resolveScanContext(
      { platform: 'htb', program: programa() },
      { LAB_CIDRS: '10.129.0.0/16' },
      semArquivo,
    );
    expect(ctx.mode).toBe('lab');
  });
});

describe('needsConfirmation', () => {
  it('só programa com automation unspecified exige confirmação', () => {
    const com = (automation: string) =>
      resolveScanContext(
        {
          platform: 'bounty',
          program: programa({
            rules: { automation, maxRequestsPerSecond: 2, testAccountsOnly: false, forbidden: [] },
          }),
        },
        {},
        semArquivo,
      );
    expect(needsConfirmation(com('unspecified'))).toBe(true);
    expect(needsConfirmation(com('allowed'))).toBe(false);
    expect(needsConfirmation(com('forbidden'))).toBe(false);
    expect(
      needsConfirmation(
        resolveScanContext({ platform: 'htb' }, { LAB_CIDRS: '10.129.0.0/16' }, semArquivo),
      ),
    ).toBe(false);
  });
});
