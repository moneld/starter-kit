import { HttpStatus } from '@nestjs/common';
import { ErrorResponse } from '../../interfaces/exception-handler.interface';
import { BaseExceptionHandler } from './base-exception.handler';

export class JwtExceptionHandler extends BaseExceptionHandler {
  canHandle(exception: any): boolean {
    return (
      exception instanceof Error &&
      [
        'JsonWebTokenError',
        'TokenExpiredError',
        'NotBeforeError',
      ].includes(exception.name)
    );
  }

  handle(exception: Error, context: any): ErrorResponse {
    const status = HttpStatus.UNAUTHORIZED;
    let message: string;
    let error: string;

    switch (exception.name) {
      case 'TokenExpiredError':
        message = 'Session expired, please login again';
        error = 'TokenExpired';
        break;
      case 'NotBeforeError':
        message = 'Token not yet valid';
        error = 'TokenNotActive';
        break;
      default:
        message = 'Invalid session, please login again';
        error = 'InvalidToken';
        break;
    }

    return this.createErrorResponse(status, message, error, context);
  }

  getPriority(): number {
    return 2;
  }
}
