import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import { DomainError, ValidationFailedError } from './errors';
import { loadEnv } from './env';
import { ScansService } from './scans.service';
import { scopeCheck } from './scope-check';

const USO = `uso:
  pnpm scan -- create --target <valor> --kind <host|url|openapi|mcp> --platform <htb|thm|local|bounty>
                      [--profile <passive|standard|deep|bounty>] [--program-id <uuid>]
  pnpm scan -- scope-check <url|host|ip> --program <nome> [--passive]
  pnpm scan -- scope-check <url|host|ip> (--ovpn <arquivo> | --lab-cidr <cidr>...) [--passive]`;

type Cmd = (args: string[], prisma: PrismaClient) => Promise<number>;

const create: Cmd = async (args, prisma) => {
  const { values } = parseArgs({
    args,
    options: {
      target: { type: 'string' },
      kind: { type: 'string' },
      platform: { type: 'string' },
      profile: { type: 'string' },
      'program-id': { type: 'string' },
    },
  });
  const { scanId } = await new ScansService(prisma).createScan({
    targetKind: values.kind,
    targetValue: values.target,
    platform: values.platform,
    profile: values.profile,
    programId: values['program-id'],
  });
  console.log(scanId);
  return 0;
};

const scopeCheckCmd: Cmd = async (args, prisma) => {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      program: { type: 'string' },
      ovpn: { type: 'string' },
      'lab-cidr': { type: 'string', multiple: true },
      passive: { type: 'boolean' },
    },
  });
  const [destination, ...extra] = positionals;
  if (!destination || extra.length > 0) {
    console.error(`informe exatamente um destino\n${USO}`);
    return 2;
  }
  const { decision, text } = await scopeCheck(prisma, {
    destination,
    ...(values.program ? { program: values.program } : {}),
    ...(values.ovpn ? { ovpn: values.ovpn } : {}),
    ...(values['lab-cidr'] ? { labCidrs: values['lab-cidr'] } : {}),
    ...(values.passive ? { passive: true } : {}),
  });
  console.log(text);
  // 0 = permitido, 1 = bloqueado (útil em scripts)
  return decision.allowed ? 0 : 1;
};

const COMANDOS: Record<string, Cmd> = { create, 'scope-check': scopeCheckCmd };

async function main(argv: string[]): Promise<number> {
  // pnpm repassa o "--" literal; descarta os iniciais.
  const args = [...argv];
  while (args[0] === '--') args.shift();
  const [nome, ...resto] = args;
  const comando = nome ? COMANDOS[nome] : undefined;

  if (!comando) {
    console.error(nome ? `comando desconhecido: ${nome}\n${USO}` : USO);
    return 2;
  }

  loadEnv();
  const prisma = new PrismaClient();
  try {
    return await comando(resto, prisma);
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
