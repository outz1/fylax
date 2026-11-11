import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

/**
 * Carrega o .env da raiz do monorepo (a pasta com pnpm-workspace.yaml).
 * Não sobrescreve variáveis já definidas no ambiente.
 */
export function loadEnv(start: string = process.cwd()): void {
  let dir = resolve(start);
  for (;;) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) {
      const file = join(dir, '.env');
      if (existsSync(file)) process.loadEnvFile(file);
      return;
    }
    const parent = dirname(dir);
    if (parent === dir) return;
    dir = parent;
  }
}
