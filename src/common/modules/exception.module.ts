import { Global, Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ExceptionHandlerRegistry } from '../exceptions/exception-handler.registry';
import { DefaultExceptionHandler } from '../exceptions/handlers/default-exception.handler';
import { HttpExceptionHandler } from '../exceptions/handlers/http-exception.handler';
import { JwtExceptionHandler } from '../exceptions/handlers/jwt-exception.handler';
import { PrismaExceptionHandler } from '../exceptions/handlers/prisma-exception.handler';
import { GlobalExceptionFilter } from '../filters/global-exception.filter';

const exceptionProviders = [
  ExceptionHandlerRegistry,
  HttpExceptionHandler,
  JwtExceptionHandler,
  PrismaExceptionHandler,
  DefaultExceptionHandler,
  {
    provide: APP_FILTER,
    useClass: GlobalExceptionFilter,
  },
];

@Global()
@Module({
  providers: exceptionProviders,
  exports: [ExceptionHandlerRegistry],
})
export class ExceptionModule {
  constructor(
    private readonly registry: ExceptionHandlerRegistry,
    private readonly httpHandler: HttpExceptionHandler,
    private readonly jwtHandler: JwtExceptionHandler,
    private readonly prismaHandler: PrismaExceptionHandler,
  ) {
    // Register all exception handlers
    this.registry.register(this.httpHandler);
    this.registry.register(this.jwtHandler);
    this.registry.register(this.prismaHandler);
  }
}
