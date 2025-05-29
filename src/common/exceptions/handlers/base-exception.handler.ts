import { HttpStatus } from '@nestjs/common';
import {
    ErrorResponse,
    IExceptionHandler,
} from '../../interfaces/exception-handler.interface';

export abstract class BaseExceptionHandler implements IExceptionHandler {
    abstract canHandle(exception: any): boolean;
    abstract handle(exception: any, context: any): ErrorResponse;
    abstract getPriority(): number;

    protected createErrorResponse(
        statusCode: HttpStatus,
        message: string | string[],
        error: string,
        context: any,
    ): ErrorResponse {
        const request = context.switchToHttp().getRequest();

        return {
            statusCode,
            message,
            error,
            timestamp: new Date().toISOString(),
            path: request.url,
            requestId: request.id,
        };
    }

    protected sanitizeErrorMessage(
        message: string,
        isProduction: boolean,
    ): string {
        if (isProduction) {
            // Sanitize sensitive information in production
            const sensitivePatterns = [
                /password/i,
                /token/i,
                /secret/i,
                /key/i,
                /credential/i,
            ];

            for (const pattern of sensitivePatterns) {
                if (pattern.test(message)) {
                    return 'An error occurred processing your request';
                }
            }
        }

        return message;
    }
}
