import { Inject, Injectable } from '@nestjs/common';
import { PasswordResetToken } from 'generated/prisma';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEncryptionService } from '../../../common/interfaces/encryption.interface';
import { PrismaService } from '../../prisma/prisma.service';
import { IPasswordResetTokenRepository } from '../interfaces/token-repository.interface';

@Injectable()
export class PasswordResetTokenRepository
  implements IPasswordResetTokenRepository {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(INJECTION_TOKENS.ENCRYPTION_SERVICE)
    private readonly encryptionService: IEncryptionService,
  ) { }

  async create(
    userId: string,
    token: string,
    expiresAt: Date,
  ): Promise<PasswordResetToken> {
    // Delete any existing password reset tokens for this user
    await this.deleteByUserId(userId);

    // Encrypt the token
    const encryptedToken = this.encryptionService.encrypt(token);

    return this.prisma.passwordResetToken.create({
      data: {
        token: encryptedToken,
        expiresAt,
        userId,
      },
    });
  }

  async findByToken(token: string): Promise<PasswordResetToken | null> {
    const passwordResetTokens =
      await this.prisma.passwordResetToken.findMany({
        where: {
          expiresAt: { gt: new Date() },
        },
        include: { user: true },
      });

    for (const passwordResetToken of passwordResetTokens) {
      try {
        const decryptedToken = this.encryptionService.decrypt(
          passwordResetToken.token,
        );
        if (decryptedToken === token) {
          return passwordResetToken;
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  async delete(id: string): Promise<void> {
    await this.prisma.passwordResetToken.delete({
      where: { id },
    });
  }

  async deleteByUserId(userId: string): Promise<void> {
    await this.prisma.passwordResetToken.deleteMany({
      where: { userId },
    });
  }
}
