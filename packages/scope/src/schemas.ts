import { z } from 'zod';
import { AUTOMATION_POLICIES, SCOPE_ENTRY_KINDS } from '@fylax/core';
import { validateScopeEntry } from './validate';

export const scopeEntrySchema = z
  .object({
    kind: z.enum(SCOPE_ENTRY_KINDS),
    value: z.string().trim().min(1),
    ports: z.array(z.number().int().min(1).max(65535)).optional(),
  })
  .superRefine((entry, ctx) => {
    // Recusa wildcard amplo (*.com), CIDR que abrange a internet (0.0.0.0/0) e URL sem http(s).
    const problema = validateScopeEntry(entry);
    if (problema) ctx.addIssue({ code: 'custom', message: problema, path: ['value'] });
  });

export const programRulesSchema = z.object({
  automation: z.enum(AUTOMATION_POLICIES),
  maxRequestsPerSecond: z.number().positive(),
  requiredHeaders: z.record(z.string(), z.string()).optional(),
  testAccountsOnly: z.boolean(),
  forbidden: z.array(z.string()),
  reviewMaxAgeDays: z.number().int().positive().optional(),
});
