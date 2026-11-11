const ROUTE = /^route\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)/;

function maskToPrefix(mask: string): number | null {
  const octets = mask.split('.').map(Number);
  let bits = 0;
  let zeroSeen = false;
  for (const o of octets) {
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    for (let i = 7; i >= 0; i--) {
      const bit = (o >> i) & 1;
      if (bit === 1) {
        if (zeroSeen) return null; // máscara não contígua
        bits++;
      } else {
        zeroSeen = true;
      }
    }
  }
  return bits;
}

/**
 * Extrai os CIDRs das linhas `route <rede> <máscara>` de um .ovpn.
 * Rotas empurradas pelo servidor não aparecem no arquivo: complemente com LAB_CIDRS.
 */
export function parseOvpnRoutes(text: string): string[] {
  const cidrs: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = ROUTE.exec(line.trim());
    if (!m) continue;
    const prefix = maskToPrefix(m[2] as string);
    if (prefix !== null) cidrs.push(`${m[1]}/${prefix}`);
  }
  return [...new Set(cidrs)];
}
