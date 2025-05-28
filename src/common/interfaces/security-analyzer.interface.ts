import { User } from 'generated/prisma';

export interface ISecurityAnalyzer {
  analyze(context: SecurityContext): Promise<SecurityAlert[]>;
  getName(): string;
  getPriority(): number;
}

export interface SecurityContext {
  user: User;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

export interface SecurityAlert {
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  details: any;
  timestamp: Date;
}
