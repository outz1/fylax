import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FakeDns } from '@fylax/scope/testing';
import { NotFoundError, ValidationFailedError } from './errors';
import { scopeCheck } from './scope-check';
import { ProgramsService } from './programs.service';

const prisma = new PrismaClient();
const programs = new ProgramsService(prisma);
const nome = `scopecheck-${process.pid}-${Date.now()}`;
const inicio = new Date();

const dns = new FakeDns({
  'api.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] },
  'cdn.exemplo.com': { addresses: ['151.101.1.1'], cnames: ['exemplo.fastly.net'] },
  'box.htb': { addresses: ['10.129.0.10'], cnames: [] },
});

beforeAll(async () => {
  await programs.createProgram({
    platform: 'hackerone',
    name: nome,
    briefUrl: 'https://hackerone.com/exemplo',
    inScope: [{ kind: 'wildcard', value: '*.exemplo.com' }],
    outOfScope: [{ kind: 'host', value: 'admin.exemplo.com' }],
    rules: {
      automation: 'allowed',
      maxRequestsPerSecond: 3,
      testAccountsOnly: false,
      forbidden: [],
    },
    reviewedAt: new Date().toISOString(),
  });
});

afterAll(async () => {
  await prisma.auditLog.deleteMany({ where: { detail: { path: ['program'], equals: nome } } });
  await prisma.auditLog.deleteMany({
    where: { detail: { path: ['mode'], equals: 'lab' }, createdAt: { gte: inicio } },
  });
  await prisma.program.deleteMany({ where: { name: nome } });
  await prisma.$disconnect();
});

describe('scope-check', () => {
  it('imprime a decisão e a regra e grava só scope.* no AuditLog (nenhum http.request)', async () => {
    const permitido = await scopeCheck(
      prisma,
      { destination: 'https://api.exemplo.com/v1', program: nome },
      { dns, env: {} },
    );
    expect(permitido.decision.allowed).toBe(true);
    expect(permitido.text).toContain('decisão: ALLOW');
    expect(permitido.text).toContain('regra: wildcard *.exemplo.com');
    expect(permitido.text).toContain('taxa máxima: 3 req/s');
    expect(permitido.text).toContain('nenhum tráfego HTTP foi enviado');

    const bloqueado = await scopeCheck(
      prisma,
      { destination: 'https://admin.exemplo.com', program: nome },
      {
        dns: new FakeDns({ 'admin.exemplo.com': { addresses: ['93.184.216.34'], cnames: [] } }),
        env: {},
      },
    );
    expect(bloqueado.decision.allowed).toBe(false);
    expect(bloqueado.text).toContain('decisão: BLOCK');
    expect(bloqueado.text).toContain('regra: host admin.exemplo.com');

    const logs = await prisma.auditLog.findMany({
      where: { detail: { path: ['program'], equals: nome } },
      orderBy: { createdAt: 'asc' },
    });
    expect(logs.map((l) => l.action)).toEqual(['scope.allow', 'scope.block']);
    expect(logs[0]?.detail).toMatchObject({
      host: 'api.exemplo.com',
      rule: { kind: 'wildcard', value: '*.exemplo.com' },
    });

    const trafego = await prisma.auditLog.count({
      where: { action: { in: ['http.request', 'tool.exec'] }, createdAt: { gte: inicio } },
    });
    expect(trafego).toBe(0);
  });

  it('CNAME de terceiro e destino interno são bloqueados com o motivo', async () => {
    const cname = await scopeCheck(
      prisma,
      { destination: 'https://cdn.exemplo.com', program: nome },
      { dns, env: {} },
    );
    expect(cname.decision.allowed).toBe(false);
    expect(cname.text).toContain('exemplo.fastly.net');

    const meta = await scopeCheck(
      prisma,
      { destination: 'http://169.254.169.254/latest/', program: nome },
      { dns, env: {} },
    );
    expect(meta.decision.allowed).toBe(false);
    expect(meta.text).toContain('bloqueio absoluto');
  });

  it('FYLAX_LAN_CIDRS do ambiente vira bloqueio absoluto', async () => {
    const r = await scopeCheck(
      prisma,
      { destination: '10.50.0.7', labCidrs: ['10.0.0.0/8'] },
      { dns, env: { FYLAX_LAN_CIDRS: '10.50.0.0/24' } },
    );
    expect(r.decision.allowed).toBe(false);
    expect(r.text).toContain('LAN configurada');
  });

  it('modo lab: --lab-cidr, --ovpn e LAB_CIDRS formam a allowlist', async () => {
    const porCidr = await scopeCheck(
      prisma,
      { destination: 'box.htb', labCidrs: ['10.129.0.0/16'] },
      { dns, env: {} },
    );
    expect(porCidr.decision.allowed).toBe(true);

    const dir = mkdtempSync(join(tmpdir(), 'fylax-ovpn-'));
    const ovpn = join(dir, 'lab.ovpn');
    writeFileSync(ovpn, 'remote vpn.example.net 1337 udp\nroute 10.129.0.0 255.255.0.0\n');
    const porOvpn = await scopeCheck(
      prisma,
      { destination: '10.129.0.10', ovpn },
      { dns, env: {} },
    );
    expect(porOvpn.decision.allowed).toBe(true);

    const porEnv = await scopeCheck(
      prisma,
      { destination: '10.129.0.10' },
      { dns, env: { LAB_CIDRS: '10.129.0.0/16' } },
    );
    expect(porEnv.decision.allowed).toBe(true);

    const fora = await scopeCheck(
      prisma,
      { destination: '93.184.216.34', labCidrs: ['10.129.0.0/16'] },
      { dns, env: {} },
    );
    expect(fora.decision.allowed).toBe(false);
  });

  it('erros de uso viram erro de validação ou not found, nunca stack trace', async () => {
    await expect(
      scopeCheck(prisma, { destination: 'x.com' }, { dns, env: {} }),
    ).rejects.toBeInstanceOf(ValidationFailedError);
    await expect(
      scopeCheck(
        prisma,
        { destination: 'x.com', program: nome, labCidrs: ['10.0.0.0/8'] },
        { dns, env: {} },
      ),
    ).rejects.toBeInstanceOf(ValidationFailedError);
    await expect(
      scopeCheck(prisma, { destination: 'x.com', labCidrs: ['0.0.0.0/0'] }, { dns, env: {} }),
    ).rejects.toBeInstanceOf(ValidationFailedError);
    await expect(
      scopeCheck(prisma, { destination: 'x.com', program: 'nao-existe-xyz' }, { dns, env: {} }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});
