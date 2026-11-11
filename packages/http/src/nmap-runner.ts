import { spawn } from 'node:child_process';

export class NmapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NmapError';
  }
}

export interface NmapRunInput {
  args: readonly string[];
  timeoutMs: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
}

export interface NmapRunOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface NmapRunner {
  run(input: NmapRunInput): Promise<NmapRunOutput>;
}

/** Executa o binário `nmap` sem shell: cada item do argv é um argumento. */
export class SpawnNmapRunner implements NmapRunner {
  constructor(private readonly binary = 'nmap') {}

  run(input: NmapRunInput): Promise<NmapRunOutput> {
    return new Promise((resolve, reject) => {
      if (input.signal?.aborted) {
        reject(new NmapError('execução do nmap cancelada'));
        return;
      }
      const child = spawn(this.binary, [...input.args], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });

      const out: Buffer[] = [];
      let outBytes = 0;
      let stderr = '';
      let failure: NmapError | undefined;

      const kill = (why: NmapError) => {
        failure ??= why;
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 2000).unref();
      };
      const timer = setTimeout(
        () => kill(new NmapError(`nmap excedeu o tempo limite de ${input.timeoutMs} ms`)),
        input.timeoutMs,
      );
      const onAbort = () => kill(new NmapError('execução do nmap cancelada'));
      input.signal?.addEventListener('abort', onAbort, { once: true });

      child.stdout.on('data', (chunk: Buffer) => {
        outBytes += chunk.length;
        if (outBytes > input.maxOutputBytes) {
          kill(new NmapError('saída do nmap excedeu o limite'));
          return;
        }
        out.push(chunk);
      });
      child.stderr.on('data', (chunk: Buffer) => {
        if (stderr.length < 2000) stderr += chunk.toString('utf8');
      });

      const finish = () => {
        clearTimeout(timer);
        input.signal?.removeEventListener('abort', onAbort);
      };
      child.on('error', (e) => {
        finish();
        const code = (e as NodeJS.ErrnoException).code;
        reject(new NmapError(code === 'ENOENT' ? 'binário nmap não encontrado' : e.message));
      });
      child.on('close', (exitCode) => {
        finish();
        if (failure) {
          reject(failure);
          return;
        }
        resolve({ stdout: Buffer.concat(out).toString('utf8'), stderr, exitCode: exitCode ?? -1 });
      });
    });
  }
}
