import type { Check } from '@fylax/core';
import { createTlsInfo, exposedService, serverBanner } from './recon/analysis';
import { httpDiscover, httpProbe } from './recon/http';
import { portScan } from './recon/port-scan';

/**
 * Módulo recon, na ordem de execução: descobre (http-probe, port-scan, http-discover) e depois
 * analisa o que foi descoberto (tls-info, server-banner, exposed-service).
 * `now` é injetável para testar a validade de certificados.
 */
export function createReconChecks(opts: { now?: () => Date } = {}): Check[] {
  return [
    httpProbe,
    portScan,
    httpDiscover,
    createTlsInfo(opts.now ?? (() => new Date())),
    serverBanner,
    exposedService,
  ];
}

export const RECON_CHECKS: Check[] = createReconChecks();

export { TLS_EXPIRY_WARNING_DAYS, certificateCoversHost } from './recon/analysis';
export { nmapProfileFor } from './recon/port-scan';
