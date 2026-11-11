// Convenção do projeto: sem travessão em texto gerado. Varre código e infra.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const RAIZES = ['apps', 'packages', 'infra', 'scripts'];
const IGNORAR = new Set(['node_modules', 'dist', 'migrations', 'check-no-emdash.mjs']);
const EXT = /\.(ts|tsx|js|mjs|json|prisma|ya?ml|sh|md)$/;
const TRAVESSAO = /[—–]/;

const achados = [];

function varrer(dir) {
  for (const nome of readdirSync(dir)) {
    if (IGNORAR.has(nome)) continue;
    const caminho = join(dir, nome);
    if (statSync(caminho).isDirectory()) {
      varrer(caminho);
    } else if (EXT.test(nome)) {
      readFileSync(caminho, 'utf8')
        .split('\n')
        .forEach((linha, i) => {
          if (TRAVESSAO.test(linha)) achados.push(`${caminho}:${i + 1}`);
        });
    }
  }
}

for (const raiz of RAIZES) {
  try {
    varrer(raiz);
  } catch {
    // pasta ainda não existe
  }
}

if (achados.length > 0) {
  console.error(
    'Travessão encontrado (use vírgula, dois pontos ou parênteses):\n' + achados.join('\n'),
  );
  process.exit(1);
}
