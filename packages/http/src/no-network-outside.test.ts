import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { describe, expect, it } from 'vitest';

// Critério de aceite da fase 1: nenhuma chamada de rede fora de packages/http.
const RAIZ = resolve(__dirname, '../../..');
const PADROES: Array<[string, RegExp]> = [
  ['fetch(', /\bfetch\s*\(/],
  ['axios', /\baxios\b/],
  ['http.request', /\bhttps?\.(request|get)\s*\(/],
  ['net.connect', /\bnet\.(connect|createConnection)\s*\(/],
  ['WebSocket', /new\s+WebSocket\s*\(/],
  ['TLS desabilitado', /rejectUnauthorized\s*:\s*false/],
  ['TLS desabilitado (env)', /NODE_TLS_REJECT_UNAUTHORIZED/],
];
const IGNORAR = new Set(['node_modules', 'dist', '.git', 'migrations']);

function arquivos(dir: string, out: string[] = []): string[] {
  for (const nome of readdirSync(dir)) {
    if (IGNORAR.has(nome)) continue;
    const caminho = join(dir, nome);
    if (statSync(caminho).isDirectory()) arquivos(caminho, out);
    else if (/\.(ts|tsx|js|mjs|cjs)$/.test(nome)) out.push(caminho);
  }
  return out;
}

describe('rede só em packages/http', () => {
  it('nenhum fetch, axios, http.request, net.connect ou TLS desabilitado fora de packages/http', () => {
    const permitido = join('packages', 'http') + sep;
    const achados: string[] = [];
    for (const raiz of ['apps', 'packages']) {
      for (const arquivo of arquivos(join(RAIZ, raiz))) {
        const rel = relative(RAIZ, arquivo);
        if (rel.startsWith(permitido)) continue;
        const linhas = readFileSync(arquivo, 'utf8').split('\n');
        linhas.forEach((linha, i) => {
          for (const [nome, regex] of PADROES) {
            if (regex.test(linha)) achados.push(`${rel}:${i + 1} (${nome})`);
          }
        });
      }
    }
    expect(achados).toEqual([]);
  });

  it('o próprio packages/http não desabilita a verificação TLS', () => {
    const achados: string[] = [];
    for (const arquivo of arquivos(join(RAIZ, 'packages', 'http'))) {
      if (arquivo.endsWith('no-network-outside.test.ts')) continue;
      readFileSync(arquivo, 'utf8')
        .split('\n')
        .forEach((linha, i) => {
          if (/rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED/.test(linha)) {
            achados.push(`${relative(RAIZ, arquivo)}:${i + 1}`);
          }
        });
    }
    expect(achados).toEqual([]);
  });
});
