import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

// Carrega o .env da raiz do monorepo (REDIS_URL) sem sobrescrever o ambiente.
let dir = resolve(process.cwd());
for (;;) {
  if (existsSync(join(dir, 'pnpm-workspace.yaml'))) {
    const file = join(dir, '.env');
    if (existsSync(file)) process.loadEnvFile(file);
    break;
  }
  const parent = dirname(dir);
  if (parent === dir) break;
  dir = parent;
}
