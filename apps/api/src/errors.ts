import type { ZodError } from 'zod';

/** Erros de domínio: o REST mapeia para 4xx e a CLI imprime sem stack trace. */
export abstract class DomainError extends Error {
  abstract readonly httpStatus: number;
  abstract readonly code: string;
}

export interface ValidationIssue {
  path: string;
  message: string;
}

export class ValidationFailedError extends DomainError {
  readonly httpStatus = 400;
  readonly code = 'validation_error';

  constructor(readonly issues: ValidationIssue[]) {
    super('Entrada inválida');
  }

  static fromZod(error: ZodError): ValidationFailedError {
    return new ValidationFailedError(
      error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    );
  }
}

export class NotFoundError extends DomainError {
  readonly httpStatus = 404;
  readonly code = 'not_found';
}

export class ConflictError extends DomainError {
  readonly httpStatus = 409;
  readonly code = 'conflict';
}
