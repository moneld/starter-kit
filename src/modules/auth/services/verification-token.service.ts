import { Inject, Injectable, Logger } from '@nestjs/common';
import { addDays } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEncryptionService } from '../../../common/interfaces/encryption.interface';
import { IVerificationTokenRepository } from '../interfaces/token-repository.interface';
import { IVerificationTokenService } from '../interfaces/token-service.interface';

@Injectable()
export class VerificationTokenService implements IVerificationTokenService {
    private readonly logger = new Logger(VerificationTokenService.name);

    constructor(
        @Inject(INJECTION_TOKENS.VERIFICATION_TOKEN_REPOSITORY)
        private readonly verificationTokenRepository: IVerificationTokenRepository,

        @Inject(INJECTION_TOKENS.ENCRYPTION_SERVICE)
        private readonly encryptionService: IEncryptionService,
    ) {}

    async createEmailVerificationToken(userId: string): Promise<string> {
        const token = this.encryptionService.generateSecureToken();
        const expiresAt = addDays(new Date(), 1); // 24 hours

        await this.verificationTokenRepository.create(userId, token, expiresAt);

        this.logger.debug(
            `Email verification token created for user: ${userId}`,
        );
        return token;
    }

    async verifyEmailToken(token: string): Promise<string | null> {
        const verificationToken =
            await this.verificationTokenRepository.findByToken(token);

        if (!verificationToken) {
            return null;
        }

        // Check if token is expired
        if (new Date() > verificationToken.expiresAt) {
            await this.verificationTokenRepository.delete(verificationToken.id);
            return null;
        }

        return verificationToken.userId;
    }
}
