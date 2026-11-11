import { Prisma, type PrismaClient } from '@prisma/client';
import {
  CHECK_MODULES,
  queueForPlatform,
  type Asset,
  type AssetSink,
  type Check,
  type CheckContext,
  type CheckModule,
  type Finding,
  type ScanProfile,
  type ScanQueueName,
  type ScopedHttpClient,
  type ScopedNmap,
  type TargetRef,
} from '@fylax/core';
import { assetDedupKey } from '@fylax/db';
import {
  ScopeContextError,
  needsConfirmation,
  resolveScanContext,
  type ScanContextEnv,
  type ScopeContext,
} from '@fylax/scope';

export type ScanOutcome = 'done' | 'failed' | 'canceled' | 'skipped';

export interface HttpFactoryArgs {
  scanId: string;
  profile: ScanProfile;
  context: ScopeContext;
}

export interface ProcessorDeps {
  prisma: PrismaClient;
  checks: readonly Check[];
  /** Fila que este worker atende; jobs de outra plataforma nunca executam aqui. */
  queue: ScanQueueName;
  env: ScanContextEnv;
  readOvpn: (path: string) => string | undefined;
  /** Cliente HTTP do scan, já com Scope Guard, rate limit e auditoria. */
  makeHttp: (args: HttpFactoryArgs) => ScopedHttpClient;
  /** nmap do scan: única forma de executá-lo, sob o Scope Guard e com auditoria tool.exec. */
  makeNmap: (args: HttpFactoryArgs) => ScopedNmap;
  assetSinkFor: (scanId: string) => AssetSink;
  checkTimeoutMs?: number;
  cancelPollMs?: number;
  now?: () => Date;
}

class CanceledError extends Error {
  constructor() {
    super('scan cancelado');
  }
}

const MAX_ERROR_LENGTH = 2000;
const truncate = (text: string): string =>
  text.length > MAX_ERROR_LENGTH ? `${text.slice(0, MAX_ERROR_LENGTH)}…` : text;
const messageOf = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const toJson = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

/**
 * O próprio alvo entra como asset de partida (só em memória), para que `appliesTo` dos checks
 * de recon tenha onde casar. Alvo host vira `service`; os demais viram `url`.
 */
function seedAssets(target: TargetRef): Asset[] {
  const base = { target: true, kind: target.kind, value: target.value };
  return target.kind === 'host'
    ? [{ type: 'service', data: { ...base, host: target.value } }]
    : [{ type: 'url', data: { ...base, url: target.value } }];
}

/** O nmap nunca roda em check passivo nem em scan passivo: a tentativa vira erro do check. */
const refuseNmap: ScopedNmap = {
  scan: async () => {
    throw new Error('nmap não roda em perfil ou check passivo');
  },
};

/** Força `passive: true` em todo request (checks passivos e escopos que proíbem automação). */
function passiveOnly(client: ScopedHttpClient): ScopedHttpClient {
  return { request: (req) => client.request({ ...req, passive: true }) };
}

/**
 * Executa um scan: reivindica, monta o escopo, roda os checks por módulo e persiste o resultado.
 * Falha fechada: sem contexto de escopo, sem confirmação exigida ou na fila errada, nenhum check roda
 * e nenhum request sai.
 */
export class ScanProcessor {
  constructor(private readonly d: ProcessorDeps) {}

  private now(): Date {
    return this.d.now?.() ?? new Date();
  }

  /** `resume`: o job foi reentregue (worker caiu no meio); retoma um scan que ficou `running`. */
  async process(scanId: string, opts: { resume?: boolean } = {}): Promise<ScanOutcome> {
    const { prisma } = this.d;
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { target: { include: { program: true } } },
    });
    if (!scan) return 'skipped';

    const platform = scan.target.platform;
    if (queueForPlatform(platform) !== this.d.queue) {
      await this.fail(scanId, `plataforma "${platform}" não é atendida pela fila ${this.d.queue}`);
      return 'failed';
    }

    // Reivindicação atômica: dois workers (ou uma entrega duplicada) nunca executam o mesmo scan.
    const claimed = await prisma.scan.updateMany({
      where: {
        id: scanId,
        OR: [{ status: 'queued' }, ...(opts.resume ? [{ status: 'running' as const }] : [])],
      },
      data: { status: 'running', startedAt: scan.startedAt ?? this.now(), error: null },
    });
    if (claimed.count === 0) return 'skipped';

    const cancel = new AbortController();
    const poll = setInterval(() => {
      prisma.scan
        .findUnique({ where: { id: scanId }, select: { status: true } })
        .then((s) => {
          if (s?.status === 'canceled') cancel.abort();
        })
        .catch(() => undefined);
    }, this.d.cancelPollMs ?? 1000);
    poll.unref();

    try {
      let context: ScopeContext;
      try {
        context = resolveScanContext(
          { platform, program: scan.target.program },
          this.d.env,
          this.d.readOvpn,
        );
      } catch (e) {
        if (e instanceof ScopeContextError) {
          await this.fail(scanId, e.message);
          return 'failed';
        }
        throw e;
      }

      if (needsConfirmation(context) && !scan.confirmedAt) {
        await this.fail(
          scanId,
          'confirmação humana ausente: este escopo exige confirm antes de executar',
        );
        return 'failed';
      }

      const target: TargetRef = {
        kind: scan.target.kind,
        value: scan.target.value,
        platform,
        ...(scan.target.programId ? { programId: scan.target.programId } : {}),
      };
      return await this.execute(scanId, scan.profile, target, context, cancel);
    } catch (e) {
      if (e instanceof CanceledError) return 'canceled';
      await this.fail(scanId, `erro interno do worker: ${messageOf(e)}`);
      return 'failed';
    } finally {
      clearInterval(poll);
    }
  }

  private async execute(
    scanId: string,
    profile: ScanProfile,
    target: TargetRef,
    context: ScopeContext,
    cancel: AbortController,
  ): Promise<ScanOutcome> {
    const { prisma } = this.d;

    // Perfil passive e programa com automação proibida: só checks passivos, e todo request é passivo.
    const onlyPassive =
      profile === 'passive' ||
      (context.mode === 'program' && context.program.rules.automation === 'forbidden');
    const selected = this.d.checks.filter((c) => !onlyPassive || c.passive === true);

    const byModule = new Map<CheckModule, Check[]>();
    for (const module of CHECK_MODULES) {
      const list = selected.filter((c) => c.module === module);
      if (list.length > 0) byModule.set(module, list);
    }
    for (const module of byModule.keys()) await this.prepareTask(scanId, module);

    const http = this.d.makeHttp({ scanId, profile, context });
    const nmap = this.d.makeNmap({ scanId, profile, context });
    const assetSink = this.d.assetSinkFor(scanId);

    const known: Asset[] = seedAssets(target);
    const seen = new Set(known.map(assetDedupKey));
    const persisted = await prisma.asset.findMany({ where: { scanId } });
    for (const row of persisted) {
      const asset: Asset = {
        type: row.type as Asset['type'],
        data: row.data as Record<string, unknown>,
      };
      seen.add(assetDedupKey(asset));
      known.push(asset);
    }

    const emitAsset = async (asset: Asset): Promise<void> => {
      const key = assetDedupKey(asset);
      if (seen.has(key)) return;
      seen.add(key);
      await assetSink.record(asset);
      known.push(asset);
    };

    try {
      for (const [module, checks] of byModule) {
        await prisma.task.updateMany({
          where: { scanId, module },
          data: { status: 'running', error: null },
        });
        const errors: string[] = [];
        let ran = 0;

        for (const check of checks) {
          // Lê o status no banco antes de cada passo: o cancelamento entre checks não espera o poll,
          // e o corpo de um check nunca começa depois de cancelado.
          if (cancel.signal.aborted || (await this.isCanceled(scanId))) {
            cancel.abort();
            throw new CanceledError();
          }
          if (!known.some((a) => check.appliesTo(a))) continue;
          ran++;

          const passive = check.passive === true || onlyPassive;
          const ctx: CheckContext = {
            scanId,
            target,
            profile,
            http: passive ? passiveOnly(http) : http,
            nmap: passive ? refuseNmap : nmap,
            assets: known,
            emitAsset,
          };
          try {
            const findings = await this.runCheck(check, ctx, cancel.signal);
            errors.push(...(await this.saveFindings(scanId, check, findings)));
          } catch (e) {
            if (e instanceof CanceledError) throw e;
            errors.push(`${check.id}: ${messageOf(e)}`);
          }
        }

        await prisma.task.updateMany({
          where: { scanId, module },
          data:
            errors.length > 0
              ? { status: 'failed', error: truncate(errors.join('; ')) }
              : { status: ran > 0 ? 'done' : 'skipped', error: null },
        });
      }
    } catch (e) {
      if (e instanceof CanceledError) {
        await prisma.task.updateMany({
          where: { scanId, status: { in: ['pending', 'running'] } },
          data: { status: 'skipped', error: 'scan cancelado' },
        });
        return 'canceled';
      }
      throw e;
    }

    // Só conclui se ainda estiver running: um cancelamento concorrente não é sobrescrito.
    const done = await prisma.scan.updateMany({
      where: { id: scanId, status: 'running' },
      data: { status: 'done', finishedAt: this.now() },
    });
    return done.count === 1 ? 'done' : 'canceled';
  }

  private async isCanceled(scanId: string): Promise<boolean> {
    const row = await this.d.prisma.scan.findUnique({
      where: { id: scanId },
      select: { status: true },
    });
    return row?.status === 'canceled';
  }

  private async prepareTask(scanId: string, module: CheckModule): Promise<void> {
    const { prisma } = this.d;
    const existing = await prisma.task.findFirst({ where: { scanId, module } });
    if (existing) {
      await prisma.task.update({
        where: { id: existing.id },
        data: { status: 'pending', attempts: { increment: 1 }, error: null },
      });
    } else {
      await prisma.task.create({ data: { scanId, module, status: 'pending', attempts: 1 } });
    }
  }

  /** Timeout por check e cancelamento: o runner segue mesmo que o check ignore o `signal`. */
  private runCheck(check: Check, ctx: CheckContext, cancel: AbortSignal): Promise<Finding[]> {
    const timeoutMs = check.timeoutMs ?? this.d.checkTimeoutMs ?? 60_000;
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = AbortSignal.any([cancel, timeout]);

    const aborted = new Promise<never>((_, reject) => {
      const onAbort = () =>
        reject(cancel.aborted ? new CanceledError() : new Error(`timeout de ${timeoutMs} ms`));
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    });
    const running = check.run({ ...ctx, signal });
    running.catch(() => undefined); // evita rejeição não tratada se o timeout vencer a corrida
    return Promise.race([running, aborted]);
  }

  /** Persiste os findings válidos e devolve os erros dos inválidos. Idempotente por dedupKey. */
  private async saveFindings(scanId: string, check: Check, findings: Finding[]): Promise<string[]> {
    const errors: string[] = [];
    const valid: Finding[] = [];
    for (const f of findings) {
      if (!f.checkId.startsWith(`${check.module}.`)) {
        errors.push(
          `${check.id}: finding com checkId "${f.checkId}" fora do módulo ${check.module}`,
        );
      } else {
        valid.push(f);
      }
    }
    if (valid.length > 0) {
      await this.d.prisma.finding.createMany({
        data: valid.map((f) => ({
          scanId,
          checkId: f.checkId,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          asset: f.asset,
          description: f.description,
          evidence: toJson(f.evidence),
          reproduction: f.reproduction,
          references: f.references,
          dedupKey: f.dedupKey,
        })),
        skipDuplicates: true,
      });
    }
    return errors;
  }

  private async fail(scanId: string, message: string): Promise<void> {
    await this.d.prisma.scan.updateMany({
      where: { id: scanId, status: { in: ['queued', 'running'] } },
      data: { status: 'failed', error: truncate(message), finishedAt: this.now() },
    });
  }
}
