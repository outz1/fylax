import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { NmapParseError, parseNmapXml } from './nmap-xml';

/**
 * Saída REAL do nmap 7.99 (`-sT -sV --version-light --script banner,ssl-cert -oX -`), capturada
 * contra as fixtures do lab local (infra/lab). Cobre o que o XML de exemplo dos outros testes não
 * tem: DOCTYPE, instrução de stylesheet, comentário com a linha de comando e o formato real do ssl-cert.
 */
const fixture = (name: string) =>
  readFileSync(join(__dirname, '__fixtures__', `nmap-${name}.xml`), 'utf8');

const only = (name: string) => {
  const hosts = parseNmapXml(fixture(name));
  expect(hosts).toHaveLength(1);
  expect(hosts[0]?.ports).toHaveLength(1);
  return hosts[0]!.ports[0]!;
};

describe('parser contra saída real do nmap', () => {
  it('web: nginx em HTTP, com versão e CPE', () => {
    const p = only('web');
    expect(p).toMatchObject({ port: 80, protocol: 'tcp', state: 'open', reason: 'syn-ack' });
    expect(p.service).toMatchObject({ name: 'http', product: 'nginx' });
    expect(p.service?.version).toMatch(/^1\.27\.\d+$/);
    expect(p.service?.cpe[0]).toMatch(/^cpe:\/a:igor_sysoev:nginx:1\.27/);
    expect(p.tls).toBeUndefined();
  });

  it('tls: túnel ssl e certificado lido do ssl-cert (assunto, emissor, SAN e validade de 5 dias)', () => {
    const p = only('tls');
    expect(p.port).toBe(443);
    expect(p.service?.tunnel).toBe('ssl');
    expect(p.tls?.subject).toBe('commonName=fixture.invalid/organizationName=Fylax Lab');
    expect(p.tls?.issuer).toBe('commonName=fixture.invalid/organizationName=Fylax Lab');
    expect(p.tls?.san).toEqual(['fixture.invalid']);

    const before = Date.parse(`${p.tls?.notBefore}Z`);
    const after = Date.parse(`${p.tls?.notAfter}Z`);
    expect(Number.isNaN(before)).toBe(false);
    expect(Number.isNaN(after)).toBe(false);
    expect(Math.round((after - before) / 86_400_000)).toBe(5);
  });

  it('ssh: OpenSSH com versão, CPE e banner', () => {
    const p = only('ssh');
    expect(p).toMatchObject({ port: 22 });
    expect(p.service).toMatchObject({ name: 'ssh', product: 'OpenSSH' });
    expect(p.service?.version).toMatch(/^9\./);
    expect(p.service?.banner).toMatch(/^SSH-2\.0-OpenSSH_9/);
    expect(p.service?.cpe[0]).toMatch(/^cpe:\/a:openbsd:openssh/);
  });

  it('redis: serviço identificado na porta 6379', () => {
    const p = only('redis');
    expect(p.port).toBe(6379);
    expect(p.service?.name).toBe('redis');
  });

  it('XML real cortado em qualquer ponto vira erro, nunca "nenhuma porta"', () => {
    const xml = fixture('tls');
    for (const fracao of [0.3, 0.5, 0.7, 0.9, 0.98]) {
      expect(
        () => parseNmapXml(xml.slice(0, Math.floor(xml.length * fracao))),
        `corte em ${fracao}`,
      ).toThrow(NmapParseError);
    }
  });
});
