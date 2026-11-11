import { z } from 'zod';
import {
  CHECK_MODULES,
  SCAN_PROFILES,
  SEVERITIES,
  TARGET_KINDS,
  TARGET_PLATFORMS,
} from '@fylax/core';
import { programRulesSchema, scopeEntrySchema } from '@fylax/scope';
import { ValidationFailedError } from './errors';

export function parse<S extends z.ZodType>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(input);
  if (!result.success) throw ValidationFailedError.fromZod(result.error);
  return result.data;
}

export const createScanSchema = z
  .object({
    targetKind: z.enum(TARGET_KINDS),
    targetValue: z.string().trim().min(1).max(2048),
    platform: z.enum(TARGET_PLATFORMS),
    profile: z.enum(SCAN_PROFILES).default('standard'),
    programId: z.uuid().optional(),
  })
  .refine((v) => v.platform !== 'bounty' || v.programId !== undefined, {
    path: ['programId'],
    message: 'platform "bounty" exige programId',
  });
export type CreateScanInput = z.input<typeof createScanSchema>;

export const idSchema = z.uuid();

export const findingsQuerySchema = z.object({
  severity: z.enum(SEVERITIES).optional(),
  module: z.enum(CHECK_MODULES).optional(),
});

// scopeEntrySchema e programRulesSchema vivem em @fylax/scope (API e worker validam igual).
export { scopeEntrySchema, programRulesSchema };

const CINCO_MINUTOS_MS = 5 * 60 * 1000;

export const createProgramSchema = z.object({
  platform: z.string().trim().min(1),
  name: z.string().trim().min(1),
  briefUrl: z.url(),
  inScope: z.array(scopeEntrySchema).min(1, 'inScope precisa de ao menos uma entrada'),
  outOfScope: z.array(scopeEntrySchema).default([]),
  rules: programRulesSchema,
  // Uma data futura burlaria a regra de "brief precisa de nova revisão" (fase 1).
  reviewedAt: z.coerce
    .date()
    .refine((d) => d.getTime() <= Date.now() + CINCO_MINUTOS_MS, 'reviewedAt não pode ser futuro'),
});
