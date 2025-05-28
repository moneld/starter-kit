import {
  BadRequestException,
  Inject,
  Injectable,
  Logger
} from '@nestjs/common';
import { addDays } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { v4 as uuidv4 } from 'uuid';
import { IEmailService } from '../../mail/interfaces/email-provider.interface';
import { IUserRepository } from '../../users/interfaces/user-repository.interface';
import { IVerificationTokenRepository } from '../interfaces/token-repository.interface';

@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
    @Inject(INJECTION_TOKENS.VERIFICATION_TOKEN_REPOSITORY)
    private readonly verificationTokenRepository: IVerificationTokenRepository,
    @Inject(INJECTION_TOKENS.EMAIL_SERVICE)
    private readonly emailService: IEmailService,
  ) { }

  async createVerificationToken(userId: string): Promise<string> {
    const token = uuidv4();
    const expiresAt = addDays(new Date(), 1); // 24 hours

    await this.verificationTokenRepository.create(userId, token, expiresAt);

    return token;
  }

  async sendVerificationEmail(email: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      // Don't reveal if email exists
      return;
    }

    if (user.isEmailVerified) {
      return;
    }

    const token = await this.createVerificationToken(user.id);
    await this.emailService.sendVerificationEmail(
      user.email,
      token,
      user.firstName || undefined,
    );

    this.logger.log(`Verification email sent to: ${email}`);
  }

  async verifyEmail(token: string): Promise<void> {
    const verificationToken =
      await this.verificationTokenRepository.findByToken(token);
    if (!verificationToken) {
      throw new BadRequestException(
        'Invalid or expired verification token',
      );
    }

    // Mark email as verified
    await this.userRepository.verifyEmail(verificationToken.userId);

    // Delete used token
    await this.verificationTokenRepository.delete(verificationToken.id);

    // Send welcome email
    const user = await this.userRepository.findById(
      verificationToken.userId,
    );
    if (user) {
      await this.emailService.sendWelcomeEmail(
        user.email,
        user.firstName || undefined,
      );
    }

    this.logger.log(`Email verified for user: ${verificationToken.userId}`);
  }
}
