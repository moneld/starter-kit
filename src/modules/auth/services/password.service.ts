import {
    BadRequestException,
    Inject,
    Injectable,
    Logger,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { addMinutes } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { v4 as uuidv4 } from 'uuid';
import { IHashingService } from '../../../common/interfaces/hashing.interface';
import { IEmailService } from '../../mail/interfaces/email-provider.interface';
import { IUserRepository } from '../../users/interfaces/user-repository.interface';
import { IPasswordService } from '../interfaces/password-service.interface';
import {
    IPasswordResetTokenRepository,
    IRefreshTokenRepository,
} from '../interfaces/token-repository.interface';

@Injectable()
export class PasswordService implements IPasswordService {
    private readonly logger = new Logger(PasswordService.name);

    constructor(
        @Inject(INJECTION_TOKENS.USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(INJECTION_TOKENS.PASSWORD_RESET_TOKEN_REPOSITORY)
        private readonly passwordResetTokenRepository: IPasswordResetTokenRepository,
        @Inject(INJECTION_TOKENS.HASHING_SERVICE)
        private readonly hashingService: IHashingService,
        @Inject(INJECTION_TOKENS.EMAIL_SERVICE)
        private readonly emailService: IEmailService,
        @Inject(INJECTION_TOKENS.REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: IRefreshTokenRepository,
    ) {}

    async changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string,
    ): Promise<void> {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        // Verify current password
        const isPasswordValid = await this.hashingService.verify(
            currentPassword,
            user.password,
        );
        if (!isPasswordValid) {
            throw new UnauthorizedException('Current password is incorrect');
        }

        // Validate new password strength
        if (!this.validatePasswordStrength(newPassword)) {
            throw new BadRequestException(
                'New password does not meet security requirements',
            );
        }

        // Hash and update password
        const hashedPassword = await this.hashingService.hash(newPassword);
        await this.userRepository.updatePassword(userId, hashedPassword);

        // Revoke all refresh tokens
        await this.refreshTokenRepository.revokeAllByUserId(userId);

        this.logger.log(`Password changed successfully for user: ${userId}`);
    }

    async forgotPassword(email: string): Promise<void> {
        try {
            const user = await this.userRepository.findByEmail(email);
            if (!user) {
                // Don't reveal if email exists
                return;
            }

            // Generate reset token
            const token = uuidv4();
            const expiresAt = addMinutes(new Date(), 60); // 1 hour

            await this.passwordResetTokenRepository.create(
                user.id,
                token,
                expiresAt,
            );

            // Send reset email
            await this.emailService.sendPasswordResetEmail(
                user.email,
                token,
                user.firstName || undefined,
            );

            this.logger.log(`Password reset requested for: ${email}`);
        } catch (error) {
            this.logger.error(`Error in forgot password: ${error.message}`);
            // Don't throw error to prevent email enumeration
        }
    }

    async resetPassword(token: string, newPassword: string): Promise<void> {
        const resetToken =
            await this.passwordResetTokenRepository.findByToken(token);
        if (!resetToken) {
            throw new BadRequestException('Invalid or expired reset token');
        }

        // Validate password strength
        if (!this.validatePasswordStrength(newPassword)) {
            throw new BadRequestException(
                'Password does not meet security requirements',
            );
        }

        // Hash and update password
        const hashedPassword = await this.hashingService.hash(newPassword);
        await this.userRepository.updatePassword(
            resetToken.userId,
            hashedPassword,
        );

        // Delete used token
        await this.passwordResetTokenRepository.delete(resetToken.id);

        // Revoke all refresh tokens
        await this.refreshTokenRepository.revokeAllByUserId(resetToken.userId);

        this.logger.log(
            `Password reset completed for user: ${resetToken.userId}`,
        );
    }

    validatePasswordStrength(password: string): boolean {
        // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
        const passwordRegex =
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return passwordRegex.test(password);
    }
}
