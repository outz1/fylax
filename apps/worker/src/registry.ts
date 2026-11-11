import type { Check } from '@fylax/core';

/**
 * Checks registrados. Vazio na etapa 2a (orquestração): o módulo recon entra na 2b,
 * seguido de web, api e mcp. Todo check novo é registrado aqui e tem teste.
 */
export const CHECKS: Check[] = [];
