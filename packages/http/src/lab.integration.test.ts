import { spawn, spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { ScopeGuard, ScopeResolver, ScopeViolationError, type ScopeContext } from '@fylax/scope';
import { FakeDns, MemoryAudit } from '@fylax/scope/testing';
import { ScopedNmap } from './nmap';
import {
  SpawnNmapRunner,
  type NmapRunInput,
  type NmapRunOutput,
  type NmapRunner,
} from './nmap-runner';

/**
 * Teste 15 da spec da fase 2: nmap REAL contra as fixtures do lab local (infra/lab), dentro do
 * namespace de rede do `worker-local` (firewall do `lab-gw`). Pula se o lab não estiver de pé:
 * suba com `pnpm lab:up`. O tráfego fica todo dentro do Docker; nada vai para a internet.
 */
const WORKER = 'fylax-worker-local-1';
const GATEWAY = 'fylax-lab-gw-1';
const FIXTURES = ['fylax-lab-web-1', 'fylax-lab-tls-1', 'fylax-lab-ssh-1', 'fylax-lab-redis-1'];

function running(names: string[]): boolean {
  const r = spawnSync('docker', ['ps', '--format', '{{.Names}}'], {
    encoding: 'utf8',
    timeout: 20_000,
  });
  if (r.status !== 0) return false;
  const up = new Set(r.stdout.split('\n').map((s) => s.trim()));
  return names.every((n) => up.has(n));
}

const LAB_UP = running([WORKER, GATEWAY, ...FIXTURES]);

/** Executa o nmap DENTRO do container do worker local (namespace do lab-gw), como em produção. */
class DockerExecRunner implements NmapRunner {
  readonly calls: NmapRunInput[] = [];
  private readonly inner = new SpawnNmapRunner('docker');
  async run(input: NmapRunInput): Promise<NmapRunOutput> {
    this.calls.push(input);
    return this.inner.run({ ...input, args: ['exec', WORKER, 'nmap', ...input.args] });
  }
}

const LAB: ScopeContext = { mode: 'lab', allowlist: ['10.250.0.0/24'] };

function setup() {
  const audit = new MemoryAudit();
  const guard = new ScopeGuard(new ScopeResolver({ dns: new FakeDns({}) }), audit);
  const runner = new DockerExecRunner();
  const nmap = new ScopedNmap({ guard, context: LAB, audit, scanId: 'lab-it', runner });
  return { nmap, audit, runner };
}

/** nmap direto, sem o ScopedNmap, para provar o que o FIREWALL deixa passar. */
function rawState(ip: string, port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'docker',
      [
        'exec',
        WORKER,
        'nmap',
        '-sT',
        '--unprivileged',
        '-Pn',
        '-n',
        '-T4',
        '--max-retries',
        '0',
        '--host-timeout',
        '20s',
        '-p',
        String(port),
        '-oG',
        '-',
        ip,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let out = '';
    child.stdout.on('data', (c: Buffer) => (out += c.toString('utf8')));
    child.on('error', reject);
    child.on('close', () => {
      const m = new RegExp(`${port}/(open|closed|filtered)`).exec(out);
      resolve(m?.[1] ?? 'sem-resposta');
    });
  });
}

describe.skipIf(!LAB_UP)('15. nmap real contra o lab local (precisa de `pnpm lab:up`)', () => {
  const PORTS = [22, 80, 443, 6379];

  it('cada fixture é identificada com serviço, produto e versão', async () => {
    const { nmap } = setup();
    const por = async (ip: string) =>
      (await nmap.scan({ host: ip, profile: 'standard', ports: PORTS })).hosts[0]?.ports ?? [];

    const web = await por('10.250.0.10');
    expect(web.map((p) => p.port)).toEqual([80]);
    expect(web[0]?.service).toMatchObject({ name: 'http', product: 'nginx' });

    const tls = await por('10.250.0.11');
    expect(tls.map((p) => p.port)).toEqual([443]);
    expect(tls[0]?.service?.tunnel).toBe('ssl');
    expect(tls[0]?.tls).toMatchObject({
      san: ['fixture.invalid'],
      subject: expect.stringContaining('commonName=fixture.invalid'),
    });

    const ssh = await por('10.250.0.12');
    expect(ssh.map((p) => p.port)).toEqual([22]);
    expect(ssh[0]?.service).toMatchObject({ name: 'ssh', product: 'OpenSSH' });
    expect(ssh[0]?.service?.banner).toMatch(/^SSH-2\.0-OpenSSH/);

    const redis = await por('10.250.0.13');
    expect(redis.map((p) => p.port)).toEqual([6379]);
    expect(redis[0]?.service?.name).toBe('redis');
  }, 120_000);

  it('REGRESSÃO: o perfil standard completo encontra o Redis (6379), que o top-1000 do nmap perderia', async () => {
    const { nmap, audit, runner } = setup();
    const res = await nmap.scan({ host: '10.250.0.13', profile: 'standard' }); // sem lista de portas: vale o perfil
    expect(res.hosts[0]?.ports.map((p) => p.port)).toContain(6379);

    const argv = runner.calls[0]?.args ?? [];
    expect(argv).not.toContain('--top-ports');
    expect(argv[argv.indexOf('-p') + 1]).toContain('6379');
    const [start, end] = audit.entries.filter((e) => e.action === 'tool.exec');
    expect(start?.detail).toMatchObject({ phase: 'start', host: '10.250.0.13', mode: 'lab' });
    expect(end?.detail).toMatchObject({ phase: 'end', exitCode: 0, openPorts: 1 });
  }, 180_000);

  it('alvo fora da allowlist: o Scope Guard bloqueia e o nmap nem é executado', async () => {
    const { nmap, audit, runner } = setup();
    for (const host of [
      '10.250.1.5',
      '172.31.250.10',
      '192.168.1.11',
      '127.0.0.1',
      '169.254.169.254',
    ]) {
      await expect(nmap.scan({ host, profile: 'standard' }), host).rejects.toBeInstanceOf(
        ScopeViolationError,
      );
    }
    expect(runner.calls).toHaveLength(0);
    expect(audit.actions().every((a) => a === 'scope.block')).toBe(true);
  }, 60_000);

  it('a segunda camada: o firewall do lab-gw só deixa passar o lab e o Postgres/Redis (kill switch)', async () => {
    // permitido: o lab e o serviço interno declarado em ALLOW_INTERNAL
    expect(await rawState('10.250.0.13', 6379)).toBe('open');
    expect(await rawState('172.31.250.10', 5432)).toBe('open');
    // bloqueado: outra porta do mesmo Postgres, o outro container de rede, o gateway do Docker e um IP externo
    for (const [ip, port] of [
      ['172.31.250.10', 80],
      ['172.31.250.2', 80], // o container vpn
      ['172.31.250.1', 80], // gateway da rede do Docker
      ['192.0.2.1', 80], // TEST-NET-1: se o firewall falhasse, sairia para a internet
    ] as const) {
      expect(await rawState(ip, port), `${ip}:${port}`).not.toBe('open');
      expect(await rawState(ip, port), `${ip}:${port}`).not.toBe('closed'); // closed = RST = a rede respondeu
    }
  }, 120_000);
});
