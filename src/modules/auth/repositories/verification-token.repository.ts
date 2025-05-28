import { Inject, Injectable } from '@nestjs/common';
import { VerificationToken } from 'generated/prisma';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEncryptionService } from '../../../common/interfaces/encryption.interface';
import { PrismaService } from '../../prisma/prisma.service';
import { IVerificationTokenRepository } from '../interfaces/token-repository.interface';

@Injectable()
export class VerificationTokenRepository
  implements IVerificationTokenRepository {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(INJECTION_TOKENS.ENCRYPTION_SERVICE)
    private readonly encryptionService: IEncryptionService,
  ) { }

  async create(
    userId: string,
    token: string,
    expiresAt: Date,
  ): Promise<VerificationToken> {
    // Delete any existing verification tokens for this user
    await this.deleteByUserId(userId);

    // Encrypt the token
    const encryptedToken = this.encryptionService.encrypt(token);

    return this.prisma.verificationToken.create({
      data: {
        token: encryptedToken,
        expiresAt,
        userId,
      },
    });
  }

  async findByToken(token: string): Promise<VerificationToken | null> {
    const verificationTokens = await this.prisma.verificationToken.findMany(
      {
        where: {
          expiresAt: { gt: new Date() },
        },
        include: { user: true },
      },
    );

    for (const verificationToken of verificationTokens) {
      try {
        const decryptedToken = this.encryptionService.decrypt(
          verificationToken.token,
        );
        if (decryptedToken === token) {
          return verificationToken;
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  async delete(id: string): Promise<void> {
    await this.prisma.verificationToken.delete({
      where: { id },
    });
  }

  async deleteByUserId(userId: string): Promise<void> {
    await this.prisma.verificationToken.deleteMany({
      where: { userId },
    });
  }
}
