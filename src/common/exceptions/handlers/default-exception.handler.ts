import { HttpStatus } from '@nestjs/common';
import { ErrorResponse } from '../../interfaces/exception-handler.interface';
import { BaseExceptionHandler } from './base-exception.handler';

export class DefaultExceptionHandler extends BaseExceptionHandler {
    canHandle(exception: any): boolean {
        return true; // Handles all exceptions not handled by other handlers
    }

    handle(exception: any, context: any): ErrorResponse {
        const status = HttpStatus.INTERNAL_SERVER_ERROR;
        let message = 'An internal error occurred';
        let error = 'InternalServerError';

        if (exception instanceof Error) {
            const isProduction = process.env.NODE_ENV === 'production';
            if (!isProduction) {
                message = exception.message || message;
                error = exception.name || error;
            }
        }

        return this.createErrorResponse(status, message, error, context);
    }

    getPriority(): number {
        return 999; // Lowest priority - catch all
    }
}
