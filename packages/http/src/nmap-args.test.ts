import { describe, expect, it } from 'vitest';
import { SENSITIVE_PORTS } from '@fylax/core';
import {
  ALT_WEB_PORTS,
  FORBIDDEN_NMAP_FLAGS,
  MAX_PORTS,
  NMAP_PROFILE_TABLE,
  NMAP_SCRIPTS,
  NmapArgsError,
  assertArgvSafe,
  buildNmapArgs,
  formatRate,
  planNmap,
} from './nmap-args';

/** Toda flag que o argv pode conter. Qualquer coisa fora daqui é um bug. */
const ALLOWED_FLAGS = new Set([
  '-sT',
  '--unprivileged',
  '-Pn',
  '-n',
  '--open',
  '--max-retries',
  '--host-timeout',
  '-T3',
  '--max-rate',
  '--top-ports',
  '--exclude-ports',
  '-p',
  '-sV',
  '--version-light',
  '--version-intensity',
  '--script',
  '-oX',
  '--',
]);

const flagsOf = (args: string[]): string[] => {
  const end = args.indexOf('--');
  // O "-" isolado é o valor de `-oX` (stdout), não uma flag.
  return args
    .slice(0, end === -1 ? args.length : end + 1)
    .filter((a) => a.startsWith('-') && a !== '-');
};

describe('buildNmapArgs: lista fechada', () => {
  for (const profile of ['standard', 'deep'] as const) {
    it(`${profile}: só flags permitidas, nenhuma proibida, script e alvos no lugar certo`, () => {
      const args = buildNmapArgs({ profile, ips: ['10.250.0.10', '10.250.0.11'], maxRate: 1000 });

      for (const flag of flagsOf(args)) expect(ALLOWED_FLAGS.has(flag), flag).toBe(true);
      for (const proibida of FORBIDDEN_NMAP_FLAGS) expect(args).not.toContain(proibida);

      // varredura de conexão completa, sem privilégio, sem DNS
      expect(args).toEqual(
        expect.arrayContaining(['-sT', '--unprivileged', '-Pn', '-n', '--open']),
      );
      // um único --script, com a lista fechada
      expect(args.filter((a) => a === '--script')).toHaveLength(1);
      expect(args[args.indexOf('--script') + 1]).toBe(NMAP_SCRIPTS);
      expect(NMAP_SCRIPTS).toBe('banner,ssl-cert');
      // saída XML na stdout, nada de arquivo
      expect(args.slice(args.indexOf('-oX'), args.indexOf('-oX') + 2)).toEqual(['-oX', '-']);
      // alvos só depois do "--"
      expect(args.slice(args.indexOf('--') + 1)).toEqual(['10.250.0.10', '10.250.0.11']);
      expect(() => assertArgvSafe(args)).not.toThrow();
    });
  }

  it('perfis: portas, versão e taxa vêm da tabela', () => {
    const std = buildNmapArgs({ profile: 'standard', ips: ['10.250.0.10'], maxRate: 1000 });
    expect(std).toEqual(expect.arrayContaining(['-sV', '--version-light']));
    expect(std).not.toContain('--top-ports');
    expect(std[std.indexOf('-p') + 1]).toBe(NMAP_PROFILE_TABLE.standard.portSpec);
    expect(std[std.indexOf('--max-rate') + 1]).toBe(String(NMAP_PROFILE_TABLE.standard.maxRate));

    const deep = buildNmapArgs({ profile: 'deep', ips: ['10.250.0.10'], maxRate: 1000 });
    expect(deep).toEqual(expect.arrayContaining(['--version-intensity', '7']));
    expect(deep).not.toContain('--version-light');
    expect(deep).not.toContain('--top-ports');
    expect(deep[deep.indexOf('-p') + 1]).toBe('1-65535');
    expect(deep[deep.indexOf('--max-rate') + 1]).toBe(String(NMAP_PROFILE_TABLE.deep.maxRate));
  });

  it('REGRESSÃO: o perfil standard cobre toda porta sensível e as web alternativas (Redis, MongoDB, etc.)', () => {
    // O top-1000 do nmap deixa Redis (6379) e MongoDB (27017) de fora; a lista explícita não pode.
    const spec = NMAP_PROFILE_TABLE.standard.portSpec;
    const cobre = (porta: number) =>
      spec.split(',').some((parte) => {
        const [a, b] = parte.split('-').map(Number);
        return b === undefined ? a === porta : porta >= (a as number) && porta <= b;
      });
    for (const porta of Object.keys(SENSITIVE_PORTS).map(Number)) {
      expect(cobre(porta), `porta sensível ${porta}`).toBe(true);
    }
    for (const porta of ALT_WEB_PORTS) expect(cobre(porta), `web alternativa ${porta}`).toBe(true);
    for (const porta of [1, 22, 80, 443, 1024]) expect(cobre(porta), `porta ${porta}`).toBe(true);
    expect(cobre(6379)).toBe(true);
    expect(cobre(27017)).toBe(true);
    expect(cobre(65000)).toBe(false); // standard não é deep
  });

  it('a taxa efetiva é o menor entre o perfil e o escopo', () => {
    const rate = (maxRate: number) => {
      const a = buildNmapArgs({ profile: 'standard', ips: ['10.250.0.10'], maxRate });
      return a[a.indexOf('--max-rate') + 1];
    };
    expect(rate(1)).toBe('1');
    expect(rate(20)).toBe('20');
    expect(rate(Infinity)).toBe('50'); // escopo sem teto: vale o do perfil
    expect(rate(5000)).toBe('50'); // o teto do perfil vale
    expect(formatRate(0.333333)).toBe('0.33');
  });

  it('o --host-timeout acompanha a taxa e as portas (nunca desiste do host antes de terminar)', () => {
    const timeout = (profile: 'standard' | 'deep', maxRate: number) => {
      const p = planNmap({ profile, ips: ['10.250.0.10'], maxRate });
      return { sec: p.hostTimeoutSec, arg: p.args[p.args.indexOf('--host-timeout') + 1] };
    };
    const portas = NMAP_PROFILE_TABLE.standard.portCount;
    // 50 req/s: ~21 s de varredura, margem dobrada e 120 s de base
    expect(timeout('standard', 1000).sec).toBe(Math.ceil((portas / 50) * 2) + 120);
    // 1 req/s (programa sem política de automação): o timeout cresce junto, em vez de ficar fixo
    const lento = timeout('standard', 1);
    expect(lento.sec).toBe(portas * 2 + 120);
    expect(lento.sec).toBeGreaterThan(timeout('standard', 1000).sec);
    expect(lento.arg).toBe(`${lento.sec}s`);
    // deep em 100 req/s cabe no teto
    expect(timeout('deep', 1000).sec).toBe(Math.ceil((65535 / 100) * 2) + 120);
  });

  it('taxa que torna o perfil impraticável falha com erro claro, antes de qualquer tráfego', () => {
    // standard a 0.5 req/s e deep a 5 req/s passariam do teto de 1 h: melhor recusar do que escanear pela metade
    expect(() => planNmap({ profile: 'standard', ips: ['10.250.0.10'], maxRate: 0.5 })).toThrow(
      'impraticável a 0.5 req/s',
    );
    expect(() => planNmap({ profile: 'deep', ips: ['10.250.0.10'], maxRate: 5 })).toThrow(
      'impraticável a 5 req/s',
    );
    expect(() => planNmap({ profile: 'deep', ips: ['10.250.0.10'], maxRate: 5 })).toThrow(
      NmapArgsError,
    );
    // com portas explícitas e poucas, até taxa baixa serve
    expect(() =>
      planNmap({ profile: 'deep', ips: ['10.250.0.10'], maxRate: 0.5, ports: [22, 80, 443] }),
    ).not.toThrow();
  });

  it('portas explícitas substituem --top-ports, sem duplicar e ordenadas', () => {
    const a = buildNmapArgs({
      profile: 'standard',
      ips: ['10.250.0.10'],
      maxRate: 5,
      ports: [443, 80, 443],
    });
    expect(a[a.indexOf('-p') + 1]).toBe('80,443');
    expect(a).not.toContain('--exclude-ports');
  });
});

describe('buildNmapArgs: entradas hostis são recusadas', () => {
  const base = { profile: 'standard', ips: ['10.250.0.10'], maxRate: 5 } as const;

  it('só IP: nome de host, vazio e lixo são recusados', () => {
    for (const ips of [
      ['exemplo.com'],
      ['10.250.0.10 -sS'],
      ['10.250.0.10; rm -rf /'],
      ['-sS'],
      ['--script=vuln'],
      ['10.250.0.0/24'],
      ['10.250.0.1-20'],
      [''],
      [],
    ]) {
      expect(() => buildNmapArgs({ ...base, ips }), JSON.stringify(ips)).toThrow(NmapArgsError);
    }
  });

  it('aceita IPv4 e IPv6 literais', () => {
    expect(() => buildNmapArgs({ ...base, ips: ['10.250.0.10', '2001:db8::1'] })).not.toThrow();
  });

  it('portas fora do intervalo, não inteiras ou em excesso são recusadas', () => {
    for (const ports of [[0], [65536], [-1], [1.5], [], [80, 99999]]) {
      expect(() => buildNmapArgs({ ...base, ports }), JSON.stringify(ports)).toThrow(NmapArgsError);
    }
    const demais = Array.from({ length: MAX_PORTS + 1 }, (_, i) => i + 1);
    expect(() => buildNmapArgs({ ...base, ports: demais })).toThrow(NmapArgsError);
  });

  it('perfil e taxa inválidos são recusados', () => {
    expect(() => buildNmapArgs({ ...base, profile: 'passive' as never })).toThrow(NmapArgsError);
    expect(() => buildNmapArgs({ ...base, profile: 'agressivo' as never })).toThrow(NmapArgsError);
    for (const maxRate of [0, -1, NaN]) {
      expect(() => buildNmapArgs({ ...base, maxRate })).toThrow(NmapArgsError);
    }
  });
});

describe('assertArgvSafe: defesa em profundidade', () => {
  const ok = () => buildNmapArgs({ profile: 'standard', ips: ['10.250.0.10'], maxRate: 5 });

  it('recusa cada flag proibida, sozinha ou com =valor', () => {
    for (const flag of FORBIDDEN_NMAP_FLAGS) {
      expect(() => assertArgvSafe([...ok(), flag]), flag).toThrow(NmapArgsError);
      expect(() => assertArgvSafe([...ok(), `${flag}=x`]), flag).toThrow(NmapArgsError);
    }
  });

  it('recusa script diferente, ausente ou repetido', () => {
    const trocar = (valor: string) => {
      const a = ok();
      a[a.indexOf('--script') + 1] = valor;
      return a;
    };
    expect(() => assertArgvSafe(trocar('vuln'))).toThrow(/scripts NSE/);
    expect(() => assertArgvSafe(trocar('banner,ssl-cert,http-vuln-cve2017-5638'))).toThrow(
      /scripts NSE/,
    );
    expect(() =>
      assertArgvSafe(ok().filter((a) => a !== '--script' && a !== NMAP_SCRIPTS)),
    ).toThrow(/scripts NSE/);
    expect(() => assertArgvSafe([...ok(), '--script', 'banner,ssl-cert'])).toThrow(/scripts NSE/);
  });
});
