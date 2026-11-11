import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import { DomainError, ValidationFailedError } from './errors';
import { loadEnv } from './env';
import { ScansService } from './scans.service';

const USO = `uso:
  pnpm scan -- create --target <valor> --kind <host|url|openapi|mcp> --platform <htb|thm|local|bounty>
                      [--profile <passive|standard|deep|bounty>] [--program-id <uuid>]`;

async function main(argv: string[]): Promise<number> {
  // pnpm repassa o "--" literal; descarta os iniciais.
  const args = [...argv];
  while (args[0] === '--') args.shift();
  const [comando, ...resto] = args;

  if (comando !== 'create') {
    console.error(comando ? `comando desconhecido: ${comando}\n${USO}` : USO);
    return 2;
  }

  const { values } = parseArgs({
    args: resto,
    options: {
      target: { type: 'string' },
      kind: { type: 'string' },
      platform: { type: 'string' },
      profile: { type: 'string' },
      'program-id': { type: 'string' },
    },
  });

  loadEnv();
  const prisma = new PrismaClient();
  try {
    const { scanId } = await new ScansService(prisma).createScan({
      targetKind: values.kind,
      targetValue: values.target,
      platform: values.platform,
      profile: values.profile,
      programId: values['program-id'],
    });
    console.log(scanId);
    return 0;
  } catch (e) {
    if (e instanceof ValidationFailedError) {
      console.error('erro de validação:');
      for (const i of e.issues) console.error(`  ${i.path || '(raiz)'}: ${i.message}`);
      console.error(USO);
      return 2;
    }
    if (e instanceof DomainError) {
      console.error(`erro: ${e.message}`);
      return 2;
    }
    throw e;
  } finally {
    await prisma.$disconnect();
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  },
);
