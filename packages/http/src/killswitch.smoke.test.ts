import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Teste 10 da spec da fase 1: com o container `vpn` sem tun0 ativa, um request do worker falha
 * (kill switch) e não vaza pela rota padrão.
 *
 * Todo o tráfego é entre containers locais do Docker; nada sai para a internet. Pula se não houver Docker.
 * "Worker" = um container no namespace de rede do vpn (`--network container:<vpn>`), como em produção.
 */

const VPN_DIR = resolve(__dirname, '../../../infra/vpn');
const IMAGE = 'fylax-vpn:test';
const ALPINE = 'alpine:3.20';
const SUFIXO = `${process.pid}`;
const NOMES = {
  srv: `fylax-ks-srv-${SUFIXO}`,
  vpnFechado: `fylax-ks-vpn-fechado-${SUFIXO}`,
  vpnLab: `fylax-ks-vpn-lab-${SUFIXO}`,
};

function docker(args: string[], timeoutMs = 120_000): string {
  return execFileSync('docker', args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function temDocker(): boolean {
  const r = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 20_000 });
  return r.status === 0;
}

/** Roda um wget curto; devolve true se a requisição teve sucesso. */
function alcanca(args: string[], url: string): boolean {
  const r = spawnSync(
    'docker',
    ['run', '--rm', ...args, ALPINE, 'wget', '-q', '-T', '4', '-O-', url],
    {
      encoding: 'utf8',
      timeout: 60_000,
    },
  );
  return r.status === 0;
}

function esperar(cond: () => boolean, ms = 30_000): void {
  const fim = Date.now() + ms;
  while (Date.now() < fim) {
    if (cond()) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  throw new Error('timeout esperando condição');
}

const DOCKER_OK = temDocker();

describe.skipIf(!DOCKER_OK)('10. kill switch do container vpn (smoke de rede)', () => {
  let srvIp = '';

  beforeAll(() => {
    docker(['build', '-q', '-t', IMAGE, VPN_DIR], 240_000);
    // Servidor alvo local com duas portas: 8080 (será o "endpoint VPN" permitido) e 9090 (nunca permitida).
    docker([
      'run',
      '-d',
      '--name',
      NOMES.srv,
      ALPINE,
      'sh',
      '-c',
      'for p in 8080 9090; do (while true; do printf "HTTP/1.0 200 OK\\r\\n\\r\\nvivo\\n" | nc -l -p $p; done) & done; wait',
    ]);
    esperar(() => docker(['inspect', '-f', '{{.State.Running}}', NOMES.srv]) === 'true');
    srvIp = docker([
      'inspect',
      '-f',
      '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',
      NOMES.srv,
    ]);
    // Controle: sem firewall o alvo É alcançável. Prova que a falha dos testes vem do kill switch.
    esperar(() => alcanca([], `http://${srvIp}:8080/`));
  }, 300_000);

  afterAll(() => {
    for (const nome of Object.values(NOMES))
      spawnSync('docker', ['rm', '-f', nome], { stdio: 'ignore' });
  });

  it('sem .ovpn e sem tun0: firewall fechado e o worker não alcança nada', () => {
    docker([
      'run',
      '-d',
      '--name',
      NOMES.vpnFechado,
      '--cap-add',
      'NET_ADMIN',
      '--device',
      '/dev/net/tun',
      IMAGE,
    ]);
    esperar(() => /-P OUTPUT DROP/.test(execSafe(NOMES.vpnFechado, ['iptables', '-S', 'OUTPUT'])));

    const regras = docker(['exec', NOMES.vpnFechado, 'iptables', '-S']);
    expect(regras).toContain('-P INPUT DROP');
    expect(regras).toContain('-P FORWARD DROP');
    expect(regras).toContain('-P OUTPUT DROP');
    // Só loopback na saída: nenhuma regra libera tráfego externo.
    const saidas = regras.split('\n').filter((l) => l.startsWith('-A OUTPUT'));
    expect(saidas).toEqual(['-A OUTPUT -o lo -j ACCEPT']);

    // Sem tun0.
    expect(
      spawnSync('docker', ['exec', NOMES.vpnFechado, 'ip', 'link', 'show', 'tun0']).status,
    ).not.toBe(0);
    // O container segue de pé (a rede do worker depende dele), só que fechado.
    expect(docker(['inspect', '-f', '{{.State.Running}}', NOMES.vpnFechado])).toBe('true');

    // O worker, no namespace do vpn, NÃO alcança o alvo que o controle alcança.
    const rede = ['--network', `container:${NOMES.vpnFechado}`];
    expect(alcanca(rede, `http://${srvIp}:8080/`)).toBe(false);
    expect(alcanca(rede, `http://${srvIp}:9090/`)).toBe(false);
  }, 120_000);

  it('com .ovpn: só o endpoint da VPN é alcançável pela interface padrão; o resto fica bloqueado', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fylax-ks-'));
    writeFileSync(
      join(dir, 'lab.ovpn'),
      [`remote ${srvIp} 8080 tcp`, 'route 10.129.0.0 255.255.0.0', 'dev tun'].join('\n'),
    );
    docker([
      'run',
      '-d',
      '--name',
      NOMES.vpnLab,
      '--cap-add',
      'NET_ADMIN',
      '--device',
      '/dev/net/tun',
      '-e',
      'FIREWALL_ONLY=1',
      '-e',
      'LAB_CIDRS=10.10.10.0/24',
      '-v',
      `${dir}:/vpn:ro`,
      IMAGE,
    ]);
    esperar(() => execSafe(NOMES.vpnLab, ['iptables', '-S', 'OUTPUT']).includes(`-d ${srvIp}/32`));

    const saidas = docker(['exec', NOMES.vpnLab, 'iptables', '-S', 'OUTPUT']).split('\n');
    expect(saidas).toContain('-P OUTPUT DROP');
    expect(saidas).toContain('-A OUTPUT -o lo -j ACCEPT');
    expect(saidas).toContain(`-A OUTPUT -d ${srvIp}/32 -p tcp -m tcp --dport 8080 -j ACCEPT`);
    // CIDRs do lab só pela tun+ (rota do .ovpn e LAB_CIDRS), nunca por eth0.
    expect(saidas).toContain('-A OUTPUT -d 10.129.0.0/16 -o tun+ -j ACCEPT');
    expect(saidas).toContain('-A OUTPUT -d 10.10.10.0/24 -o tun+ -j ACCEPT');
    expect(
      saidas.filter(
        (l) => l.startsWith('-A OUTPUT') && !l.includes('tun+') && !l.includes('-o lo'),
      ),
    ).toHaveLength(1);

    const rede = ['--network', `container:${NOMES.vpnLab}`];
    expect(alcanca(rede, `http://${srvIp}:8080/`)).toBe(true); // endpoint do servidor VPN: permitido
    expect(alcanca(rede, `http://${srvIp}:9090/`)).toBe(false); // mesmo IP, outra porta: bloqueado
  }, 120_000);

  it('configuração inválida mantém o firewall fechado (CIDR amplo demais)', () => {
    const nome = `${NOMES.vpnLab}-amplo`;
    try {
      const dir = mkdtempSync(join(tmpdir(), 'fylax-ks-'));
      writeFileSync(join(dir, 'lab.ovpn'), `remote ${srvIp} 8080 tcp\n`);
      docker([
        'run',
        '-d',
        '--name',
        nome,
        '--cap-add',
        'NET_ADMIN',
        '--device',
        '/dev/net/tun',
        '-e',
        'LAB_CIDRS=0.0.0.0/0',
        '-v',
        `${dir}:/vpn:ro`,
        IMAGE,
      ]);
      esperar(() => logsDe(nome).includes('CIDR amplo demais'));
      expect(docker(['inspect', '-f', '{{.State.Running}}', nome])).toBe('true');
      expect(alcanca(['--network', `container:${nome}`], `http://${srvIp}:9090/`)).toBe(false);
    } finally {
      spawnSync('docker', ['rm', '-f', nome], { stdio: 'ignore' });
    }
  }, 120_000);
});

/** O entrypoint loga em stderr; `docker logs` repassa cada fluxo no seu: junta os dois. */
function logsDe(container: string): string {
  const r = spawnSync('docker', ['logs', container], { encoding: 'utf8' });
  return `${r.stdout}${r.stderr}`;
}

function execSafe(container: string, cmd: string[]): string {
  const r = spawnSync('docker', ['exec', container, ...cmd], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout : '';
}
