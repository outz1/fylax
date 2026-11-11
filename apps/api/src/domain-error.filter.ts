import { Catch, type ArgumentsHost, type ExceptionFilter } from '@nestjs/common';
import { DomainError, ValidationFailedError } from './errors';

/** Só o que o filtro usa da resposta (evita depender dos tipos do express). */
interface JsonResponse {
  status(code: number): { json(body: unknown): void };
}

/** Erro de domínio vira 4xx com corpo estável; nunca 500. */
@Catch(DomainError)
export class DomainErrorFilter implements ExceptionFilter {
  catch(error: DomainError, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<JsonResponse>();
    res.status(error.httpStatus).json({
      error: error.code,
      message: error.message,
      ...(error instanceof ValidationFailedError ? { issues: error.issues } : {}),
    });
  }
}
