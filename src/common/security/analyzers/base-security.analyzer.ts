import { Logger } from '@nestjs/common';
import {
  ISecurityAnalyzer,
  SecurityAlert,
  SecurityContext,
} from '../../interfaces/security-analyzer.interface';

export abstract class BaseSecurityAnalyzer implements ISecurityAnalyzer {
  protected readonly logger: Logger;

  constructor(protected readonly name: string) {
    this.logger = new Logger(this.constructor.name);
  }

  abstract analyze(context: SecurityContext): Promise<SecurityAlert[]>;

  getName(): string {
    return this.name;
  }

  abstract getPriority(): number;

  protected createAlert(
    type: string,
    severity: SecurityAlert['severity'],
    message: string,
    details: any,
  ): SecurityAlert {
    return {
      type,
      severity,
      message,
      details,
      timestamp: new Date(),
    };
  }
}
