import { PrismaClient } from '@prisma/client';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { NotFoundError, ValidationFailedError } from './errors';
import { ScansService } from './scans.service';

const prisma = new PrismaClient();
const service = new ScansService(prisma);

// Valor único por execução: não colide com dados reais e permite limpar só o que o teste criou.
const alvo = (sufixo: string) => `teste-${process.pid}-${Date.now()}-${sufixo}.invalid`;
const criados: string[] = [];

afterEach(async () => {
  const targets = await prisma.target.findMany({ where: { value: { in: criados } } });
  const ids = targets.map((t) => t.id);
  await prisma.scan.deleteMany({ where: { targetId: { in: ids } } });
  await prisma.target.deleteMany({ where: { id: { in: ids } } });
  criados.length = 0;
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('createScan (banco real)', () => {
  it('grava o Scan com status queued e retorna o scanId', async () => {
    const value = alvo('a');
    criados.push(value);

    const { scanId } = await service.createScan({
      targetKind: 'host',
      targetValue: value,
      platform: 'htb',
      profile: 'standard',
    });

    const scan = await prisma.scan.findUniqueOrThrow({
      where: { id: scanId },
      include: { target: true },
    });
    expect(scan.status).toBe('queued');
    expect(scan.startedAt).toBeNull();
    expect(scan.profile).toBe('standard');
    expect(scan.target).toMatchObject({ kind: 'host', value, platform: 'htb' });
  });

  it('reaproveita o Target quando o mesmo alvo é escaneado de novo', async () => {
    const value = alvo('b');
    criados.push(value);
    const entrada = { targetKind: 'host', targetValue: value, platform: 'thm' };

    const a = await service.createScan(entrada);
    const b = await service.createScan(entrada);

    expect(a.scanId).not.toBe(b.scanId);
    expect(await prisma.target.count({ where: { value } })).toBe(1);
    expect(await prisma.scan.count({ where: { target: { value } } })).toBe(2);
  });

  it('kind inválido rejeita e não grava nada', async () => {
    const value = alvo('c');
    criados.push(value);

    await expect(
      service.createScan({ targetKind: 'ftp', targetValue: value, platform: 'htb' }),
    ).rejects.toBeInstanceOf(ValidationFailedError);
    expect(await prisma.target.count({ where: { value } })).toBe(0);
  });

  it('bounty com programId inexistente retorna NotFoundError (não 500)', async () => {
    const value = alvo('d');
    criados.push(value);

    await expect(
      service.createScan({
        targetKind: 'url',
        targetValue: `https://${value}`,
        platform: 'bounty',
        programId: '00000000-0000-4000-8000-000000000000',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});
