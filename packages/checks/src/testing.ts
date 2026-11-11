import type {
  Asset,
  Check,
  CheckContext,
  Finding,
  NmapRequest,
  NmapResult,
  ScanProfile,
  ScopedHttpClient,
  ScopedNmap,
  ScopedRequest,
  ScopedResponse,
  TargetRef,
} from '@fylax/core';

export function response(
  over: Partial<ScopedResponse> & { headers?: Record<string, string> } = {},
): ScopedResponse {
  return { status: 200, headers: {}, body: '', bytes: 0, ...over };
}

export class FakeHttp implements ScopedHttpClient {
  readonly requests: ScopedRequest[] = [];
  constructor(private readonly handler: (req: ScopedRequest) => ScopedResponse | Error) {}
  async request(req: ScopedRequest): Promise<ScopedResponse> {
    this.requests.push(req);
    const r = this.handler(req);
    if (r instanceof Error) throw r;
    return r;
  }
}

export class FakeNmap implements ScopedNmap {
  readonly calls: NmapRequest[] = [];
  constructor(private readonly result: NmapResult | Error = { hosts: [], durationMs: 1 }) {}
  async scan(req: NmapRequest): Promise<NmapResult> {
    this.calls.push(req);
    if (this.result instanceof Error) throw this.result;
    return this.result;
  }
}

export function transportError(code: string): Error {
  const e = new Error(`falha de transporte: ${code}`) as Error & { code: string };
  e.name = 'TransportError';
  e.code = code;
  return e;
}

export function seedFor(target: TargetRef): Asset[] {
  const base = { target: true, kind: target.kind, value: target.value };
  return target.kind === 'host'
    ? [{ type: 'service', data: { ...base, host: target.value } }]
    : [{ type: 'url', data: { ...base, url: target.value } }];
}

export interface ScenarioInput {
  checks: Check[];
  target: TargetRef;
  profile?: ScanProfile;
  http?: ScopedHttpClient;
  nmap?: ScopedNmap;
  /** Imita o runner: perfil passive só roda checks passivos. */
  onlyPassive?: boolean;
}

/** Executa os checks na ordem, como o runner: appliesTo sobre os assets conhecidos, emissão sem duplicar. */
export async function runScenario(input: ScenarioInput) {
  const assets: Asset[] = seedFor(input.target);
  const seen = new Set(assets.map((a) => JSON.stringify([a.type, a.data])));
  const findings: Finding[] = [];
  const ran: string[] = [];

  const ctx: CheckContext = {
    scanId: 'scan-test',
    target: input.target,
    profile: input.profile ?? 'standard',
    http: input.http ?? new FakeHttp(() => response()),
    nmap: input.nmap ?? new FakeNmap(),
    assets,
    emitAsset: async (asset) => {
      const key = JSON.stringify([asset.type, asset.data]);
      if (seen.has(key)) return;
      seen.add(key);
      assets.push(asset);
    },
  };

  for (const check of input.checks) {
    if (input.onlyPassive && check.passive !== true) continue;
    if (!assets.some((a) => check.appliesTo(a))) continue;
    ran.push(check.id);
    findings.push(...(await check.run(ctx)));
  }
  return { assets, findings, ran };
}
