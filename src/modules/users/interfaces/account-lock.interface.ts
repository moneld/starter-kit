export interface IAccountLockService {
  incrementFailedAttempts(userId: string): Promise<void>;
  resetFailedAttempts(userId: string): Promise<void>;
  isLocked(userId: string): Promise<{ locked: boolean; unlockTime?: Date }>;
  lockAccount(userId: string, duration?: number): Promise<void>;
  unlockAccount(userId: string): Promise<void>;
}
