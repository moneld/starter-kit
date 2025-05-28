import { Injectable } from '@nestjs/common';
import { IExceptionHandler } from '../interfaces/exception-handler.interface';

@Injectable()
export class ExceptionHandlerRegistry {
  private handlers: IExceptionHandler[] = [];

  register(handler: IExceptionHandler): void {
    this.handlers.push(handler);
    // Sort by priority (lower number = higher priority)
    this.handlers.sort((a, b) => a.getPriority() - b.getPriority());
  }

  findHandler(exception: any): IExceptionHandler | null {
    for (const handler of this.handlers) {
      if (handler.canHandle(exception)) {
        return handler;
      }
    }
    return null;
  }

  getHandlers(): IExceptionHandler[] {
    return [...this.handlers];
  }
}
