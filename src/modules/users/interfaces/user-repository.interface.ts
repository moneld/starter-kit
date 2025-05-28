import { User } from 'generated/prisma';
import { IBaseRepository } from '../../../common/interfaces/repository.interface';

export interface IUserRepository extends IBaseRepository<User> {
  findByEmail(email: string): Promise<User | null>;
  findByIdWithTokens(id: string): Promise<User | null>;
  incrementFailedLoginAttempts(userId: string): Promise<void>;
  resetFailedLoginAttempts(userId: string): Promise<void>;
  updatePassword(userId: string, hashedPassword: string): Promise<void>;
  verifyEmail(userId: string): Promise<void>;
  lockAccount(userId: string, until: Date): Promise<void>;
  unlockAccount(userId: string): Promise<void>;
}
