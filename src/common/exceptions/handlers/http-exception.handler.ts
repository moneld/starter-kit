import { HttpException } from '@nestjs/common';
import { ErrorResponse } from '../../interfaces/exception-handler.interface';
import { BaseExceptionHandler } from './base-exception.handler';

export class HttpExceptionHandler extends BaseExceptionHandler {
    canHandle(exception: any): boolean {
        return exception instanceof HttpException;
    }

    handle(exception: HttpException, context: any): ErrorResponse {
        const status = exception.getStatus();
        const exceptionResponse = exception.getResponse();

        let message: string | string[];
        let error: string;

        if (typeof exceptionResponse === 'object') {
            message = (exceptionResponse as any).message || exception.message;
            error = (exceptionResponse as any).error || 'Error';
        } else {
            message = exceptionResponse;
            error = 'Error';
        }

        const isProduction = process.env.NODE_ENV === 'production';
        if (typeof message === 'string') {
            message = this.sanitizeErrorMessage(message, isProduction);
        }

        return this.createErrorResponse(status, message, error, context);
    }

    getPriority(): number {
        return 1; // Higher priority for HTTP exceptions
    }
}
