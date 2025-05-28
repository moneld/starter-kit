export interface IExceptionHandler {
  canHandle(exception: any): boolean;
  handle(exception: any, context: any): ErrorResponse;
  getPriority(): number;
}

export interface ErrorResponse {
  statusCode: number;
  message: string | string[];
  error: string;
  timestamp: string;
  path: string;
  requestId: string;
}
