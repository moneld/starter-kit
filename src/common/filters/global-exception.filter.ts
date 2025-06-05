import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    Injectable,
    Logger,
} from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { ExceptionHandlerRegistry } from '../exceptions/exception-handler.registry';
import { DefaultExceptionHandler } from '../exceptions/handlers/default-exception.handler';

@Catch()
@Injectable()
export class GlobalExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger(GlobalExceptionFilter.name);
    private readonly defaultHandler = new DefaultExceptionHandler();

    constructor(private readonly handlerRegistry: ExceptionHandlerRegistry) {}

    catch(exception: unknown, host: ArgumentsHost): void {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<FastifyReply>();
        const request = ctx.getRequest<FastifyRequest>();

        // Log exception details
        this.logException(exception, request);

        // Find appropriate handler
        const handler =
            this.handlerRegistry.findHandler(exception) || this.defaultHandler;

        // Handle the exception
        const errorResponse = handler.handle(exception, host);

        // Send response
        response.status(errorResponse.statusCode).send(errorResponse);
    }

    private logException(exception: unknown, request: FastifyRequest): void {
        const logContext = {
            path: request.url,
            method: request.method,
            requestId: request.id,
            ip: request.ip || 'unknown',
            userAgent: request.headers['user-agent'] || 'unknown',
            userId: (request as any).user?.id || 'anonymous',
        };

        if (exception instanceof Error) {
            this.logger.error(
                `Exception: ${exception.message}`,
                exception.stack,
                { ...logContext, exceptionName: exception.name },
            );
        } else {
            this.logger.error('Unknown exception type', undefined, {
                ...logContext,
                exception: JSON.stringify(exception),
            });
        }
    }
}
