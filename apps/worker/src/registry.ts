import type { Check } from '@fylax/core';
import { RECON_CHECKS } from '@fylax/checks';

/**
 * Checks registrados: recon na 2b; web, api e mcp entram nas etapas seguintes.
 * Todo check novo é registrado aqui e tem teste.
 */
export const CHECKS: Check[] = [...RECON_CHECKS];
