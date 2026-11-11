import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import { BullScanEnqueuer, redisConnection } from '@fylax/queue';
import { DomainError, ValidationFailedError } from './errors';
import { loadEnv } from '@fylax/db';
import { ScansService } from './scans.service';
import { scopeCheck } from './scope-check';

const USO = `uso:
  pnpm scan -- create --target <valor> --kind <host|url|openapi|mcp> --platform <htb|thm|local|bounty>
                      [--profile <passive|standard|deep|bounty>] [--program-id <uuid>]
  pnpm scan -- run <scanId>        enfileira o scan (programa com automação não especificada espera confirm)
  pnpm scan -- confirm <scanId>    confirmação humana e enfileira
  pnpm scan -- cancel <scanId>     cancela um scan queued ou running
  pnpm scan -- scope-check <url|host|ip> --program <nome> [--passive]
  pnpm scan -- scope-check <url|host|ip> (--ovpn <arquivo> | --lab-cidr <cidr>...) [--passive]`;

/** Código de saída de "run" quando o scan aguarda confirmação humana. */
const EXIT_AWAITING_CONFIRMATION = 3;

interface Deps {
  prisma: PrismaClient;
  enqueuer: BullScanEnqueuer;
}
type Cmd = (args: string[], deps: Deps) => Promise<number>;

const create: Cmd = async (args, { prisma, enqueuer }) => {
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
  const { scanId } = await new ScansService(prisma, enqueuer).createScan({
    targetKind: values.kind,
    targetValue: values.target,
    platform: values.platform,
    profile: values.profile,
    programId: values['program-id'],
  });
  console.log(scanId);
  return 0;
};

function scanIdArg(args: string[]): string | undefined {
  const { positionals } = parseArgs({ args, allowPositionals: true, options: {} });
  return positionals.length === 1 ? positionals[0] : undefined;
}

const run: Cmd = async (args, { prisma, enqueuer }) => {
  const id = scanIdArg(args);
  if (!id) {
    console.error(`informe o scanId\n${USO}`);
    return 2;
  }
  const result = await new ScansService(prisma, enqueuer).runScan(id);
  if (result.state === 'awaiting_confirmation') {
    console.log(
      `aguardando confirmação humana: o escopo do programa não especifica automação.\nconfirme com: pnpm scan -- confirm ${result.scanId}`,
    );
    return EXIT_AWAITING_CONFIRMATION;
  }
  console.log(`enfileirado em ${result.queue}: ${result.scanId}`);
  return 0;
};

const confirm: Cmd = async (args, { prisma, enqueuer }) => {
  const id = scanIdArg(args);
  if (!id) {
    console.error(`informe o scanId\n${USO}`);
    return 2;
  }
  const result = await new ScansService(prisma, enqueuer).confirmScan(id);
  console.log(
    `confirmado em ${result.confirmedAt} e enfileirado em ${result.queue}: ${result.scanId}`,
  );
  return 0;
};

const cancel: Cmd = async (args, { prisma, enqueuer }) => {
  const id = scanIdArg(args);
  if (!id) {
    console.error(`informe o scanId\n${USO}`);
    return 2;
  }
  const result = await new ScansService(prisma, enqueuer).cancelScan(id);
  console.log(`cancelado: ${result.scanId}`);
  return 0;
};

const scopeCheckCmd: Cmd = async (args, { prisma }) => {
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

const COMANDOS: Record<string, Cmd> = {
  create,
  run,
  confirm,
  cancel,
  'scope-check': scopeCheckCmd,
};

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
  // A conexão com o Redis só abre se o comando enfileirar.
  const enqueuer = new BullScanEnqueuer(
    redisConnection(process.env.REDIS_URL ?? 'redis://127.0.0.1:6379'),
  );
  try {
    return await comando(resto, { prisma, enqueuer });
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
    await enqueuer.close();
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
