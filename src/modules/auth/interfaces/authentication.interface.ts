import { User } from 'generated/prisma';

export interface IAuthenticationService {
  validateCredentials(email: string, password: string): Promise<User | null>;
  login(
    credentials: LoginCredentials,
    context?: LoginContext,
  ): Promise<LoginResult>;
  logout(refreshToken: string): Promise<void>;
  logoutAll(userId: string): Promise<void>;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginContext {
  ipAddress?: string;
  userAgent?: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  requiresTwoFactor?: boolean;
  securityAlerts?: any[];
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
  };
}
