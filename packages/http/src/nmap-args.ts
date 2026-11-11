import { isIP } from 'node:net';
import { NMAP_PROFILES, SENSITIVE_PORTS, type NmapProfile } from '@fylax/core';

/** Portas web alternativas, além das 1 a 1024. */
export const ALT_WEB_PORTS = [8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090] as const;

const WELL_KNOWN_END = 1024;

/** Portas acima de 1024 que o perfil standard também escaneia: web alternativas e serviços sensíveis. */
export function standardExtraPorts(): number[] {
  return [...new Set([...ALT_WEB_PORTS, ...Object.keys(SENSITIVE_PORTS).map(Number)])]
    .filter((p) => p > WELL_KNOWN_END)
    .sort((a, b) => a - b);
}

const STANDARD_EXTRAS = standardExtraPorts();

/**
 * Parâmetros do nmap por perfil. É uma LISTA FECHADA: o chamador só escolhe o perfil e,
 * no máximo, reduz as portas. Não existe caminho para passar flag, script ou comando próprio.
 *
 * - standard: portas 1 a 1024, web alternativas e a lista de serviços sensíveis (SENSITIVE_PORTS).
 *   Não usa `--top-ports`: o ranking do nmap deixa Redis e MongoDB fora até do top-1000.
 * - deep: todas as portas (1 a 65535).
 *
 * Mudar qualquer valor aqui é mudar a spec (docs/SPEC-FASE-2, tabela de perfis).
 */
export const NMAP_PROFILE_TABLE = {
  standard: {
    portSpec: [`1-${WELL_KNOWN_END}`, ...STANDARD_EXTRAS].join(','),
    portCount: WELL_KNOWN_END + STANDARD_EXTRAS.length,
    maxRate: 50,
    versionArgs: ['-sV', '--version-light'],
  },
  deep: {
    portSpec: '1-65535',
    portCount: 65535,
    maxRate: 100,
    versionArgs: ['-sV', '--version-intensity', '7'],
  },
} as const satisfies Record<NmapProfile, object>;

/** Únicos scripts NSE permitidos: leitura de banner e de certificado. */
export const NMAP_SCRIPTS = 'banner,ssl-cert';

export const MAX_PORTS = 1000;

/** Teto do `--host-timeout`. Acima disso o perfil é impraticável na taxa imposta pelo escopo. */
export const MAX_HOST_TIMEOUT_SEC = 3600;
const BASE_TIMEOUT_SEC = 120;

export class NmapArgsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NmapArgsError';
  }
}

export interface NmapArgsInput {
  profile: NmapProfile;
  /** IPs já validados pelo Scope Guard. Nome de host é recusado. */
  ips: readonly string[];
  /** Quando presente, substitui as portas do perfil (portas do escopo, ou subconjunto pedido). */
  ports?: readonly number[];
  /** Portas que o escopo exclui (`outOfScope` com portas). Nunca são escaneadas. */
  excludePorts?: readonly number[];
  /** Teto efetivo em pacotes por segundo (o menor entre perfil e escopo). */
  maxRate: number;
}

export interface NmapPlan {
  args: string[];
  /** Quantas portas serão tentadas por host (estimativa; vale o maior caso). */
  portCount: number;
  /** Taxa efetiva em pacotes por segundo. */
  rate: number;
  /** `--host-timeout` calculado a partir do número de portas e da taxa. */
  hostTimeoutSec: number;
}

export function formatRate(rate: number): string {
  return String(Number(rate.toFixed(2)));
}

/**
 * Planeja a execução: argv completo (sem shell, cada item é um argumento) e o `--host-timeout`.
 *
 * O timeout acompanha a taxa: com 1 req/s e mais de mil portas, um timeout fixo faria o nmap
 * desistir do host e devolver vazio, um falso negativo silencioso. Se nem o teto basta, o plano
 * falha com erro explícito em vez de escanear pela metade.
 */
export function planNmap(input: NmapArgsInput): NmapPlan {
  if (!NMAP_PROFILES.includes(input.profile)) {
    throw new NmapArgsError(`perfil de nmap inválido: ${String(input.profile)}`);
  }
  const profile = NMAP_PROFILE_TABLE[input.profile];

  if (input.ips.length === 0) throw new NmapArgsError('nenhum IP para escanear');
  for (const ip of input.ips) {
    if (isIP(ip) === 0) throw new NmapArgsError(`alvo não é um IP: ${ip}`);
  }
  // Infinity é válido: significa "o escopo não impõe teto" e o teto efetivo vira o do perfil.
  if (Number.isNaN(input.maxRate) || input.maxRate <= 0) {
    throw new NmapArgsError('taxa máxima inválida');
  }

  const checkPort = (p: number) => {
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new NmapArgsError(`porta inválida: ${p}`);
  };
  const exclude = [...new Set(input.excludePorts ?? [])].sort((a, b) => a - b);
  exclude.forEach(checkPort);

  let portArgs: string[];
  let portCount: number;
  if (input.ports) {
    const ports = [...new Set(input.ports)]
      .sort((a, b) => a - b)
      .filter((p) => !exclude.includes(p));
    if (ports.length === 0 || ports.length > MAX_PORTS) {
      throw new NmapArgsError(`lista de portas inválida (1 a ${MAX_PORTS} portas)`);
    }
    ports.forEach(checkPort);
    portArgs = ['-p', ports.join(',')];
    portCount = ports.length;
  } else {
    portArgs = ['-p', profile.portSpec];
    if (exclude.length > 0) portArgs.push('--exclude-ports', exclude.join(','));
    portCount = profile.portCount;
  }

  const rate = Math.min(profile.maxRate, input.maxRate);
  const hostTimeoutSec = Math.ceil((portCount / rate) * 2) + BASE_TIMEOUT_SEC;
  if (hostTimeoutSec > MAX_HOST_TIMEOUT_SEC) {
    throw new NmapArgsError(
      `perfil ${input.profile} impraticável a ${formatRate(rate)} req/s: ${portCount} portas exigiriam ` +
        `${hostTimeoutSec} s (máximo ${MAX_HOST_TIMEOUT_SEC} s). Use um perfil menor ou um escopo com taxa maior`,
    );
  }

  const args = [
    '-sT', // conexão TCP completa pelo sistema: sem pacotes forjados
    '--unprivileged',
    '-Pn',
    '-n', // nunca resolve DNS: o alvo já é IP
    '--open',
    '--max-retries',
    '1',
    '--host-timeout',
    `${hostTimeoutSec}s`,
    '-T3',
    '--max-rate',
    formatRate(rate),
    ...portArgs,
    ...profile.versionArgs,
    '--script',
    NMAP_SCRIPTS,
    '-oX',
    '-',
    '--',
    ...input.ips,
  ];
  return { args, portCount, rate, hostTimeoutSec };
}

/** Só o argv, para quem não precisa do plano. */
export function buildNmapArgs(input: NmapArgsInput): string[] {
  return planNmap(input).args;
}

/** Flags que jamais podem aparecer no argv (usado pelos testes e como defesa em profundidade). */
export const FORBIDDEN_NMAP_FLAGS = [
  '-sS',
  '-sU',
  '-sN',
  '-sF',
  '-sX',
  '-sA',
  '-sW',
  '-sM',
  '-sI',
  '-sO',
  '-O',
  '-A',
  '-iL',
  '-iR',
  '-oN',
  '-oG',
  '-oA',
  '-oS',
  '--script-args',
  '--script-updatedb',
  '--spoof-mac',
  '-D',
  '-S',
  '-e',
  '-f',
  '--mtu',
  '--data',
  '--data-string',
  '--data-length',
  '--proxies',
  '--resume',
  '--append-output',
  '--datadir',
  '--servicedb',
  '--versiondb',
  '--privileged',
  '--traceroute',
  '--exclude',
  '--excludefile',
] as const;

/** Defesa em profundidade: confere o argv final antes de executar. */
export function assertArgvSafe(args: readonly string[]): void {
  for (const arg of args) {
    if (FORBIDDEN_NMAP_FLAGS.some((f) => arg === f || arg.startsWith(`${f}=`))) {
      throw new NmapArgsError(`flag proibida no argv do nmap: ${arg}`);
    }
  }
  const scriptIdx = args.indexOf('--script');
  if (
    scriptIdx === -1 ||
    args[scriptIdx + 1] !== NMAP_SCRIPTS ||
    args.indexOf('--script', scriptIdx + 1) !== -1
  ) {
    throw new NmapArgsError('scripts NSE fora da lista permitida');
  }
}
