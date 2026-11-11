import type {
  AssetSink,
  AuditSink,
  ScanProfile,
  ScopedHttpClient as ScopedHttpClientContract,
  ScopedRequest,
  ScopedResponse,
} from '@fylax/core';
import {
  ScopeViolationError,
  redactUrl,
  type ScopeContext,
  type ScopeDecision,
  type ScopeGuard,
} from '@fylax/scope';
import { RateLimiter } from './rate-limiter';
import {
  TransportError,
  UndiciTransport,
  type HttpTransport,
  type TransportResponse,
} from './transport';

/** Teto de requisições por segundo, por alvo, conforme o perfil (o escopo pode reduzir mais). */
export const PROFILE_MAX_RPS: Record<ScanProfile, number> = {
  passive: 1,
  standard: 5,
  deep: 10,
  bounty: 2,
};

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const IDEMPOTENT = new Set(['GET', 'HEAD', 'OPTIONS']);
const FOLLOWS_REDIRECT = new Set(['GET', 'HEAD']);
const SENSITIVE_ON_ORIGIN_CHANGE = ['authorization', 'cookie', 'proxy-authorization'];

export interface ScopedHttpClientOptions {
  guard: ScopeGuard;
  context: ScopeContext;
  profile: ScanProfile;
  audit: AuditSink;
  /** Recebe os destinos de redirect não seguidos (asset do scan). */
  assets?: AssetSink;
  scanId?: string;
  transport?: HttpTransport;
  timeoutMs?: number;
  maxRedirects?: number;
  /** Tentativas extras após falha de transporte (só métodos idempotentes). */
  retries?: number;
  backoffBaseMs?: number;
  maxResponseBytes?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

type Pending = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
};

type Outcome =
  { kind: 'blocked'; decision: ScopeDecision } | { kind: 'response'; response: ScopedResponse };

function lowerKeys(h: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h ?? {})) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Única API de rede do projeto. Em cada request (e em cada hop de redirect):
 * Scope Guard antes, rate limit, requiredHeaders do programa, retry só em falha de transporte,
 * AuditLog http.request depois. Redirects nunca são seguidos às cegas: cada Location é revalidado.
 */
export class ScopedHttpClient implements ScopedHttpClientContract {
  private readonly limiter: RateLimiter;
  private readonly transport: HttpTransport;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;

  constructor(private readonly o: ScopedHttpClientOptions) {
    this.now = o.now ?? Date.now;
    this.sleep = o.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.limiter = new RateLimiter(this.now, this.sleep);
    this.transport = o.transport ?? new UndiciTransport();
  }

  async request(req: ScopedRequest): Promise<ScopedResponse> {
    const passive = req.passive ?? false;
    const maxRedirects = this.o.maxRedirects ?? 5;
    let current: Pending = {
      method: req.method,
      url: req.url,
      headers: lowerKeys(req.headers),
      body: req.body,
    };
    let previous: { url: string; response: ScopedResponse } | undefined;

    for (let hop = 0; ; hop++) {
      const outcome = await this.send(current, passive, hop);

      if (outcome.kind === 'blocked') {
        if (!previous) throw new ScopeViolationError(outcome.decision, current.url);
        // Destino de redirect fora de escopo: não segue, registra como asset e para.
        const reason = `destino do redirect bloqueado: ${outcome.decision.reason}`;
        await this.recordRedirect(
          current.url,
          previous.url,
          previous.response.status,
          true,
          reason,
        );
        return {
          ...previous.response,
          redirect: { location: current.url, followed: false, reason },
        };
      }

      const res = outcome.response;
      const location = res.headers['location'];
      if (!REDIRECT_STATUS.has(res.status) || !location) return res;

      let next: URL;
      try {
        next = new URL(location, current.url);
      } catch {
        return { ...res, redirect: { location, followed: false, reason: 'Location inválido' } };
      }

      const stopReason = !FOLLOWS_REDIRECT.has(current.method)
        ? `redirect de ${current.method} não é seguido`
        : hop >= maxRedirects
          ? `limite de ${maxRedirects} redirects`
          : undefined;
      if (stopReason) {
        await this.recordRedirect(next.href, current.url, res.status, false, stopReason);
        return { ...res, redirect: { location: next.href, followed: false, reason: stopReason } };
      }

      const headers = { ...current.headers };
      if (new URL(current.url).origin !== next.origin) {
        for (const h of SENSITIVE_ON_ORIGIN_CHANGE) delete headers[h];
      }
      previous = { url: current.url, response: res };
      current = { method: current.method, url: next.href, headers, body: undefined };
    }
  }

  private async send(p: Pending, passive: boolean, hop: number): Promise<Outcome> {
    const idempotent = IDEMPOTENT.has(p.method);
    const retries = idempotent ? (this.o.retries ?? 2) : 0;

    for (let attempt = 0; ; attempt++) {
      // Revalida a cada tentativa: o DNS pode ter mudado (e o IP fixado vem desta decisão).
      const decision = await this.o.guard.check(p.url, this.o.context, {
        ...(this.o.scanId ? { scanId: this.o.scanId } : {}),
        passive,
      });
      if (!decision.allowed) return { kind: 'blocked', decision };

      const pinnedIp = decision.resolvedIps[0];
      if (!pinnedIp) throw new Error('decisão permitida sem IP resolvido');

      await this.limiter.acquire(
        decision.host,
        Math.min(PROFILE_MAX_RPS[this.o.profile], decision.maxRequestsPerSecond ?? Infinity),
      );

      const started = this.now();
      try {
        const tr = await this.transport.send({
          method: p.method,
          url: p.url,
          headers: this.headersFor(p.headers),
          ...(p.body !== undefined ? { body: p.body } : {}),
          pinnedIp,
          timeoutMs: this.o.timeoutMs ?? 15_000,
          maxBytes: this.o.maxResponseBytes ?? 5 * 1024 * 1024,
        });
        await this.audited(
          p,
          decision,
          { status: tr.status, bytes: tr.bytes },
          attempt,
          hop,
          started,
          passive,
        );
        return { kind: 'response', response: toResponse(tr) };
      } catch (e) {
        if (!(e instanceof TransportError)) throw e;
        await this.audited(
          p,
          decision,
          { status: null, bytes: 0, error: e.code ?? e.message },
          attempt,
          hop,
          started,
          passive,
        );
        if (e.retryable && attempt < retries) {
          await this.sleep((this.o.backoffBaseMs ?? 500) * 2 ** attempt);
          continue;
        }
        throw e;
      }
    }
  }

  private headersFor(base: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { 'user-agent': 'fylax-vulnscan', ...base };
    if (this.o.context.mode === 'program') {
      for (const [k, v] of Object.entries(this.o.context.program.rules.requiredHeaders ?? {})) {
        headers[k.toLowerCase()] = v;
      }
    }
    return headers;
  }

  private async audited(
    p: Pending,
    decision: ScopeDecision,
    result: { status: number | null; bytes: number; error?: string },
    attempt: number,
    hop: number,
    started: number,
    passive: boolean,
  ): Promise<void> {
    await this.o.audit.record({
      scanId: this.o.scanId ?? null,
      action: 'http.request',
      detail: {
        method: p.method,
        url: redactUrl(p.url),
        status: result.status,
        bytes: result.bytes,
        ...(result.error ? { error: result.error } : {}),
        durationMs: this.now() - started,
        attempt,
        hop,
        passive,
        decision: {
          allowed: decision.allowed,
          reason: decision.reason,
          rule: decision.rule ?? null,
          requiresConfirmation: decision.requiresConfirmation ?? false,
        },
      },
    });
  }

  private async recordRedirect(
    target: string,
    from: string,
    status: number,
    blocked: boolean,
    reason: string,
  ): Promise<void> {
    await this.o.assets?.record({
      type: 'url',
      data: {
        url: redactUrl(target),
        from: redactUrl(from),
        discoveredVia: 'redirect',
        status,
        followed: false,
        blocked,
        reason,
      },
    });
  }
}

function toResponse(tr: TransportResponse): ScopedResponse {
  return {
    status: tr.status,
    headers: tr.headers,
    body: tr.body,
    bytes: tr.bytes,
    ...(tr.truncated ? { truncated: true } : {}),
  };
}
