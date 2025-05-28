import { Inject, Injectable } from '@nestjs/common';
import { RefreshToken } from 'generated/prisma';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEncryptionService } from '../../../common/interfaces/encryption.interface';
import { PrismaService } from '../../prisma/prisma.service';
import { IRefreshTokenRepository } from '../interfaces/token-repository.interface';

@Injectable()
export class RefreshTokenRepository implements IRefreshTokenRepository {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(INJECTION_TOKENS.ENCRYPTION_SERVICE)
    private readonly encryptionService: IEncryptionService,
  ) { }

  async create(data: {
    token: string;
    userId: string;
    expiresAt: Date;
    userAgent?: string;
    ipAddress?: string;
  }): Promise<RefreshToken> {
    // Encrypt the token before storing
    const encryptedToken = this.encryptionService.encrypt(data.token);

    // Delete any existing refresh tokens for this user
    await this.prisma.refreshToken.deleteMany({
      where: { userId: data.userId },
    });

    return this.prisma.refreshToken.create({
      data: {
        token: encryptedToken,
        expiresAt: data.expiresAt,
        userAgent: data.userAgent,
        ipAddress: data.ipAddress,
        userId: data.userId,
      },
    });
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    // We need to find the token by decrypting all tokens
    // This is not ideal for performance, but necessary for security
    const refreshTokens = await this.prisma.refreshToken.findMany({
      where: {
        expiresAt: { gt: new Date() },
        isRevoked: false,
      },
      include: { user: true },
    });

    for (const refreshToken of refreshTokens) {
      try {
        const decryptedToken = this.encryptionService.decrypt(
          refreshToken.token,
        );
        if (decryptedToken === token) {
          return refreshToken;
        }
      } catch {
        // Skip tokens that can't be decrypted
        continue;
      }
    }

    return null;
  }

  async findActiveByUserId(userId: string): Promise<RefreshToken[]> {
    return this.prisma.refreshToken.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
        isRevoked: false,
      },
    });
  }

  async revokeByToken(token: string): Promise<boolean> {
    const refreshToken = await this.findByToken(token);
    if (!refreshToken) {
      return false;
    }

    await this.prisma.refreshToken.delete({
      where: { id: refreshToken.id },
    });

    return true;
  }

  async revokeAllByUserId(userId: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }

  async deleteExpired(): Promise<number> {
    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        OR: [{ expiresAt: { lt: new Date() } }, { isRevoked: true }],
      },
    });
    return result.count;
  }
}
