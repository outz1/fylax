import { describe, expect, it } from 'vitest';
import { NmapParseError, parseNmapXml } from './nmap-xml';

const wrap = (hosts: string) =>
  `<?xml version="1.0"?><nmaprun scanner="nmap" args="x" start="1"><scaninfo type="connect"/>${hosts}<runstats><finished/></runstats></nmaprun>`;

const HTTP_PORT = `
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/>
  <service name="http" product="nginx" version="1.27.2" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx:1.27.2</cpe></service>
</port>`;

const TLS_PORT = `
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/>
  <service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/>
  <script id="ssl-cert" output="Subject: commonName=fixture.invalid"><table key="subject"><elem key="commonName">fixture.invalid</elem><elem key="organizationName">Fylax Lab</elem></table><table key="issuer"><elem key="commonName">fixture.invalid</elem></table><table key="extensions"><table><elem key="name">X509v3 Subject Alternative Name</elem><elem key="value">DNS:fixture.invalid, DNS:www.fixture.invalid, IP Address:10.250.0.11</elem></table><table><elem key="name">X509v3 Basic Constraints</elem><elem key="value">CA:TRUE</elem></table></table><table key="validity"><elem key="notBefore">2026-11-01T10:00:00</elem><elem key="notAfter">2026-11-06T10:00:00</elem></table></script>
</port>`;

describe('parseNmapXml', () => {
  it('lê host, portas abertas, serviço, versão e CPE', () => {
    const xml = wrap(
      `<host><status state="up"/><address addr="10.250.0.10" addrtype="ipv4"/><ports>${HTTP_PORT}</ports></host>`,
    );
    expect(parseNmapXml(xml)).toEqual([
      {
        ip: '10.250.0.10',
        ports: [
          {
            port: 80,
            protocol: 'tcp',
            state: 'open',
            reason: 'syn-ack',
            service: {
              name: 'http',
              product: 'nginx',
              version: '1.27.2',
              cpe: ['cpe:/a:igor_sysoev:nginx:1.27.2'],
            },
          },
        ],
      },
    ]);
  });

  it('lê o certificado do script ssl-cert: assunto, emissor, SAN e validade', () => {
    const xml = wrap(
      `<host><address addr="10.250.0.11" addrtype="ipv4"/><ports>${TLS_PORT}</ports></host>`,
    );
    const port = parseNmapXml(xml)[0]?.ports[0];
    expect(port?.service?.tunnel).toBe('ssl');
    expect(port?.tls).toEqual({
      subject: 'commonName=fixture.invalid/organizationName=Fylax Lab',
      issuer: 'commonName=fixture.invalid',
      san: ['fixture.invalid', 'www.fixture.invalid', '10.250.0.11'],
      notBefore: '2026-11-01T10:00:00',
      notAfter: '2026-11-06T10:00:00',
    });
  });

  it('lê o banner e o trunca', () => {
    const longo = 'A'.repeat(1000);
    const xml = wrap(
      `<host><address addr="10.250.0.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.7"/><script id="banner" output="  SSH-2.0-OpenSSH_9.7 ${longo}  "/></port></ports></host>`,
    );
    const svc = parseNmapXml(xml)[0]?.ports[0]?.service;
    expect(svc?.banner?.startsWith('SSH-2.0-OpenSSH_9.7')).toBe(true);
    expect(svc?.banner?.length).toBe(300);
  });

  it('decodifica entidades XML', () => {
    const xml = wrap(
      `<host><address addr="10.250.0.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="Open&amp;SSH" extrainfo="protocol 2.0 &lt;ok&gt;"/></port></ports></host>`,
    );
    const svc = parseNmapXml(xml)[0]?.ports[0]?.service;
    expect(svc?.product).toBe('Open&SSH');
    expect(svc?.extraInfo).toBe('protocol 2.0 <ok>');
  });

  it('ignora portas fechadas, filtradas e UDP', () => {
    const xml = wrap(
      `<host><address addr="10.250.0.10" addrtype="ipv4"/><ports>
        <port protocol="tcp" portid="81"><state state="closed" reason="conn-refused"/></port>
        <port protocol="tcp" portid="82"><state state="filtered" reason="no-response"/></port>
        <port protocol="udp" portid="53"><state state="open" reason="udp-response"/></port>
        ${HTTP_PORT}
      </ports></host>`,
    );
    expect(parseNmapXml(xml)[0]?.ports.map((p) => p.port)).toEqual([80]);
  });

  it('vários hosts, host sem portas e sem endereço', () => {
    const xml = wrap(
      `<host><address addr="10.250.0.10" addrtype="ipv4"/><ports>${HTTP_PORT}</ports></host>
       <host><address addr="10.250.0.11" addrtype="ipv4"/></host>
       <host><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>`,
    );
    const hosts = parseNmapXml(xml);
    expect(hosts.map((h) => [h.ip, h.ports.length])).toEqual([
      ['10.250.0.10', 1],
      ['10.250.0.11', 0],
    ]);
  });

  it('nenhum host (alvo desligado) devolve lista vazia', () => {
    expect(parseNmapXml(wrap(''))).toEqual([]);
  });

  it('ignora portas com id inválido e certificado sem validade', () => {
    const xml = wrap(
      `<host><address addr="10.250.0.10" addrtype="ipv4"/><ports>
        <port protocol="tcp" portid="0"><state state="open" reason="x"/></port>
        <port protocol="tcp" portid="70000"><state state="open" reason="x"/></port>
        <port protocol="tcp" portid="443"><state state="open" reason="x"/><script id="ssl-cert" output="x"><table key="subject"><elem key="commonName">a</elem></table></script></port>
      </ports></host>`,
    );
    const ports = parseNmapXml(xml)[0]?.ports ?? [];
    expect(ports.map((p) => p.port)).toEqual([443]);
    expect(ports[0]?.tls).toBeUndefined();
  });

  it('XML malformado ou sem <nmaprun> vira NmapParseError', () => {
    for (const ruim of ['', 'não é xml', '<nmaprun><host>', '<outra/>', '<?xml version="1.0"?>']) {
      expect(() => parseNmapXml(ruim), ruim).toThrow(NmapParseError);
    }
  });

  it('saída TRUNCADA (nmap morto no meio) é erro, nunca "nenhuma porta aberta"', () => {
    const completo = wrap(
      `<host><address addr="10.250.0.10" addrtype="ipv4"/><ports>${HTTP_PORT}</ports></host>`,
    );
    expect(parseNmapXml(completo)[0]?.ports).toHaveLength(1);
    // corta em vários pontos: dentro da porta, dentro do host, antes do fechamento do nmaprun
    for (const corte of [
      completo.indexOf('<service'),
      completo.indexOf('</ports>'),
      completo.length - 15,
    ]) {
      expect(() => parseNmapXml(completo.slice(0, corte)), `corte em ${corte}`).toThrow(
        NmapParseError,
      );
    }
  });
});
