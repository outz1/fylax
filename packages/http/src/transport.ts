import { Agent, request } from 'undici';

export interface TransportRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  /** IP já validado pelo Scope Guard: a conexão vai SEMPRE para ele (anula DNS rebinding). */
  pinnedIp: string;
  timeoutMs: number;
  maxBytes: number;
}

export interface TransportResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  bytes: number;
  truncated: boolean;
}

export class TransportError extends Error {
  constructor(
    message: string,
    readonly code: string | undefined,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = 'TransportError';
  }
}

export interface HttpTransport {
  send(req: TransportRequest): Promise<TransportResponse>;
}

/** Timeouts de VPN e reset de máquina de lab: vale tentar de novo. Erro de certificado nunca. */
const RETRYABLE = new Set([
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'EPIPE',
  'ABORT_ERR',
  'TimeoutError',
]);

function errorCode(e: unknown): string | undefined {
  const err = e as { code?: string; name?: string; cause?: { code?: string } };
  return err.code ?? err.cause?.code ?? err.name;
}

function flattenHeaders(
  raw: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v)
      ? v.join(k.toLowerCase() === 'set-cookie' ? '\n' : ', ')
      : v;
  }
  return out;
}

/**
 * Transporte real. Verificação TLS fica no padrão (nunca desabilitada) e redirects NUNCA são
 * seguidos aqui: quem decide é o ScopedHttpClient, revalidando cada destino.
 */
export class UndiciTransport implements HttpTransport {
  async send(req: TransportRequest): Promise<TransportResponse> {
    const family = req.pinnedIp.includes(':') ? 6 : 4;
    const agent = new Agent({
      connect: {
        timeout: req.timeoutMs,
        lookup: (_host, options, callback) => {
          if (options && (options as { all?: boolean }).all) {
            (callback as unknown as (e: null, a: { address: string; family: number }[]) => void)(
              null,
              [{ address: req.pinnedIp, family }],
            );
          } else {
            callback(null, req.pinnedIp, family);
          }
        },
      },
    });

    try {
      const res = await request(req.url, {
        method: req.method as 'GET',
        headers: req.headers,
        ...(req.body !== undefined ? { body: req.body } : {}),
        dispatcher: agent,
        headersTimeout: req.timeoutMs,
        bodyTimeout: req.timeoutMs,
        signal: AbortSignal.timeout(req.timeoutMs),
      });

      const chunks: Buffer[] = [];
      let bytes = 0;
      let truncated = false;
      for await (const chunk of res.body) {
        const buf = Buffer.from(chunk as Uint8Array);
        if (bytes + buf.length > req.maxBytes) {
          chunks.push(buf.subarray(0, req.maxBytes - bytes));
          bytes = req.maxBytes;
          truncated = true;
          res.body.destroy();
          break;
        }
        chunks.push(buf);
        bytes += buf.length;
      }
      return {
        status: res.statusCode,
        headers: flattenHeaders(res.headers),
        body: Buffer.concat(chunks).toString('utf8'),
        bytes,
        truncated,
      };
    } catch (e) {
      const code = errorCode(e);
      throw new TransportError(
        e instanceof Error ? e.message : String(e),
        code,
        code !== undefined && RETRYABLE.has(code),
      );
    } finally {
      await agent.destroy();
    }
  }
}
