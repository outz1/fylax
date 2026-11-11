import type {
  AuditSink,
  NmapRequest,
  NmapResult,
  ScopedNmap as ScopedNmapContract,
} from '@fylax/core';
import { ScopeViolationError, type ScopeContext, type ScopeGuard } from '@fylax/scope';
import { NMAP_PROFILES } from '@fylax/core';
import { NmapArgsError, assertArgvSafe, formatRate, planNmap } from './nmap-args';
import { NmapError, SpawnNmapRunner, type NmapRunner } from './nmap-runner';
import { parseNmapXml } from './nmap-xml';

export interface ScopedNmapOptions {
  guard: ScopeGuard;
  context: ScopeContext;
  audit: AuditSink;
  scanId?: string;
  runner?: NmapRunner;
  now?: () => number;
  maxOutputBytes?: number;
}

const GRACE_MS = 30_000;

/**
 * Única forma de executar o nmap no projeto. Em cada execução:
 * 1. o Scope Guard decide sobre o alvo (e audita); bloqueado, o nmap NÃO é iniciado;
 * 2. o nmap recebe só os IPs que o Scope Guard validou, nunca o nome (sem nova resolução de DNS);
 * 3. o argv vem de uma lista fechada por perfil; a taxa é o menor valor entre perfil e escopo;
 * 4. em programa, só as portas do `inScope` (quando listadas);
 * 5. `tool.exec` é gravado ANTES de executar (se falhar, o nmap não inicia) e de novo ao terminar,
 *    sem a saída bruta.
 */
export class ScopedNmap implements ScopedNmapContract {
  private readonly runner: NmapRunner;
  private readonly now: () => number;

  constructor(private readonly o: ScopedNmapOptions) {
    this.runner = o.runner ?? new SpawnNmapRunner();
    this.now = o.now ?? Date.now;
  }

  async scan(req: NmapRequest, opts: { signal?: AbortSignal } = {}): Promise<NmapResult> {
    // Valida antes de qualquer outra coisa: perfil fora da lista (inclusive "passive") nunca executa.
    if (!NMAP_PROFILES.includes(req.profile)) {
      throw new NmapArgsError(`perfil de nmap inválido: ${String(req.profile)}`);
    }

    // O destino é só o host: pergunta se está em escopo para alguma porta (modo portless) e quais.
    const decision = await this.o.guard.check(req.host, this.o.context, {
      ...(this.o.scanId ? { scanId: this.o.scanId } : {}),
      passive: false,
      portless: true,
    });
    if (!decision.allowed) throw new ScopeViolationError(decision, req.host);
    if (decision.resolvedIps.length === 0)
      throw new NmapArgsError('decisão permitida sem IP resolvido');

    // Portas: as do escopo (se houver) e, no máximo, um subconjunto delas pedido pelo chamador,
    // sempre sem as que o outOfScope exclui.
    const scopePorts = decision.rule?.ports?.length ? decision.rule.ports : undefined;
    const excluded = decision.excludedPorts ?? [];
    const candidate = req.ports && req.ports.length > 0 ? req.ports : scopePorts;
    let ports: number[] | undefined;
    if (candidate) {
      ports = candidate.filter(
        (p) => (!scopePorts || scopePorts.includes(p)) && !excluded.includes(p),
      );
      if (ports.length === 0) throw new NmapArgsError('nenhuma das portas pedidas está no escopo');
    }

    // O plano calcula o --host-timeout a partir das portas e da taxa efetiva (menor entre perfil e
    // escopo). Se o escopo impõe uma taxa que torna o perfil impraticável, falha aqui, antes de
    // qualquer tráfego, em vez de escanear pela metade.
    const plan = planNmap({
      profile: req.profile,
      ips: decision.resolvedIps,
      ...(ports ? { ports } : {}),
      ...(!ports && excluded.length > 0 ? { excludePorts: excluded } : {}),
      maxRate: decision.maxRequestsPerSecond ?? Infinity,
    });
    const args = plan.args;
    assertArgvSafe(args);

    const base = {
      tool: 'nmap',
      host: decision.host,
      ips: decision.resolvedIps,
      profile: req.profile,
      mode: this.o.context.mode,
      program: this.o.context.mode === 'program' ? this.o.context.program.name : null,
      maxRate: formatRate(plan.rate),
      ports: plan.portCount,
      hostTimeoutSec: plan.hostTimeoutSec,
      argv: args,
    };
    const scanId = this.o.scanId ?? null;

    // Fail closed: sem registro, sem execução.
    await this.o.audit.record({ scanId, action: 'tool.exec', detail: { ...base, phase: 'start' } });

    const started = this.now();
    let exitCode: number | null = null;
    let portCount = 0;
    let error: string | undefined;
    try {
      const out = await this.runner.run({
        args,
        timeoutMs: plan.hostTimeoutSec * 1000 + GRACE_MS,
        maxOutputBytes: this.o.maxOutputBytes ?? 10 * 1024 * 1024,
        ...(opts.signal ? { signal: opts.signal } : {}),
      });
      exitCode = out.exitCode;
      if (out.exitCode !== 0) {
        throw new NmapError(
          `nmap terminou com código ${out.exitCode}: ${out.stderr.trim().slice(0, 200)}`,
        );
      }
      const requested = new Set(decision.resolvedIps);
      // Defesa em profundidade: descarta qualquer host que não tenha sido pedido.
      const hosts = parseNmapXml(out.stdout).filter((h) => requested.has(h.ip));
      portCount = hosts.reduce((n, h) => n + h.ports.length, 0);
      return { hosts, durationMs: this.now() - started };
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      await this.o.audit.record({
        scanId,
        action: 'tool.exec',
        detail: {
          ...base,
          phase: 'end',
          exitCode,
          durationMs: this.now() - started,
          openPorts: portCount,
          ...(error ? { error: error.slice(0, 200) } : {}),
        },
      });
    }
  }
}
