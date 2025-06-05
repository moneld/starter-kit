import { Inject, Injectable, Logger } from '@nestjs/common';
import { addMinutes } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEncryptionService } from '../../../common/interfaces/encryption.interface';
import { IPasswordResetTokenRepository } from '../interfaces/token-repository.interface';
import { IPasswordResetTokenService } from '../interfaces/token-service.interface';

@Injectable()
export class PasswordResetTokenService implements IPasswordResetTokenService {
    private readonly logger = new Logger(PasswordResetTokenService.name);

    constructor(
        @Inject(INJECTION_TOKENS.PASSWORD_RESET_TOKEN_REPOSITORY)
        private readonly passwordResetTokenRepository: IPasswordResetTokenRepository,
        @Inject(INJECTION_TOKENS.ENCRYPTION_SERVICE)
        private readonly encryptionService: IEncryptionService,
    ) {}

    async createPasswordResetToken(userId: string): Promise<string> {
        const token = this.encryptionService.generateSecureToken();
        const expiresAt = addMinutes(new Date(), 60); // 1 hour

        await this.passwordResetTokenRepository.create(
            userId,
            token,
            expiresAt,
        );

        this.logger.debug(`Password reset token created for user: ${userId}`);
        return token;
    }

    async verifyPasswordResetToken(token: string): Promise<string | null> {
        const resetToken =
            await this.passwordResetTokenRepository.findByToken(token);

        if (!resetToken) {
            return null;
        }

        // Check if token is expired
        if (new Date() > resetToken.expiresAt) {
            await this.passwordResetTokenRepository.delete(resetToken.id);
            return null;
        }

        return resetToken.userId;
    }
}
