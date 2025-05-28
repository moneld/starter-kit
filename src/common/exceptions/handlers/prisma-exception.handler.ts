import { HttpStatus } from '@nestjs/common';
import { Prisma } from 'generated/prisma';
import { ErrorResponse } from '../../interfaces/exception-handler.interface';
import { BaseExceptionHandler } from './base-exception.handler';

export class PrismaExceptionHandler extends BaseExceptionHandler {
  canHandle(exception: any): boolean {
    return (
      exception instanceof Prisma.PrismaClientKnownRequestError ||
      exception instanceof Prisma.PrismaClientUnknownRequestError ||
      exception instanceof Prisma.PrismaClientRustPanicError ||
      exception instanceof Prisma.PrismaClientInitializationError ||
      exception instanceof Prisma.PrismaClientValidationError
    );
  }

  handle(exception: any, context: any): ErrorResponse {
    const { httpStatus, userMessage } = this.mapPrismaError(exception);

    return this.createErrorResponse(
      httpStatus,
      userMessage,
      `Database Error${exception.code ? ` (${exception.code})` : ''}`,
      context,
    );
  }

  getPriority(): number {
    return 3;
  }

  private mapPrismaError(exception: any): {
    httpStatus: HttpStatus;
    userMessage: string;
  } {
    if (exception.code) {
      switch (exception.code) {
        case 'P2002':
          return {
            httpStatus: HttpStatus.CONFLICT,
            userMessage:
              this.formatUniqueConstraintError(exception),
          };
        case 'P2025':
          return {
            httpStatus: HttpStatus.NOT_FOUND,
            userMessage: 'The requested record does not exist',
          };
        case 'P2003':
          return {
            httpStatus: HttpStatus.BAD_REQUEST,
            userMessage:
              'Operation failed due to missing related data',
          };
        case 'P2011':
          return {
            httpStatus: HttpStatus.BAD_REQUEST,
            userMessage: `Required field '${exception.meta?.target || 'unknown'}' cannot be empty`,
          };
        case 'P2024':
          return {
            httpStatus: HttpStatus.SERVICE_UNAVAILABLE,
            userMessage:
              'Database service is temporarily unavailable',
          };
        default:
          return {
            httpStatus: HttpStatus.BAD_REQUEST,
            userMessage: 'Invalid data provided',
          };
      }
    }

    if (exception instanceof Prisma.PrismaClientValidationError) {
      return {
        httpStatus: HttpStatus.BAD_REQUEST,
        userMessage: 'Invalid data format',
      };
    }

    if (exception instanceof Prisma.PrismaClientInitializationError) {
      return {
        httpStatus: HttpStatus.SERVICE_UNAVAILABLE,
        userMessage: 'Database service is temporarily unavailable',
      };
    }

    return {
      httpStatus: HttpStatus.INTERNAL_SERVER_ERROR,
      userMessage: 'A database error occurred',
    };
  }

  private formatUniqueConstraintError(exception: any): string {
    const target = exception.meta?.target;
    if (Array.isArray(target) && target.length > 0) {
      const fields = target.join(', ');
      return `A record with this ${fields} already exists`;
    }
    return 'A record with this data already exists';
  }
}
