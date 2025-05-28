import {
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { User } from 'generated/prisma';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IHashingService } from '../../../common/interfaces/hashing.interface';
import { AnomalyDetectionService } from '../../../common/services/anomaly-detection.service';
import { IAccountLockService } from '../../users/interfaces/account-lock.interface';
import { IUserRepository } from '../../users/interfaces/user-repository.interface';
import {
  IAuthenticationService,
  LoginContext,
  LoginCredentials,
  LoginResult,
} from '../interfaces/authentication.interface';
import { IRefreshTokenRepository } from '../interfaces/token-repository.interface';
import { IJwtTokenService } from '../interfaces/token-service.interface';

@Injectable()
export class AuthenticationService implements IAuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  constructor(
    @Inject(INJECTION_TOKENS.USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
    @Inject(INJECTION_TOKENS.JWT_TOKEN_SERVICE)
    private readonly jwtTokenService: IJwtTokenService,
    @Inject(INJECTION_TOKENS.HASHING_SERVICE)
    private readonly hashingService: IHashingService,
    @Inject(INJECTION_TOKENS.ACCOUNT_LOCK_SERVICE)
    private readonly accountLockService: IAccountLockService,
    @Inject(INJECTION_TOKENS.REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepository: IRefreshTokenRepository,
    private readonly anomalyDetectionService: AnomalyDetectionService,
  ) { }

  async validateCredentials(
    email: string,
    password: string,
  ): Promise<User | null> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      return null;
    }

    const isPasswordValid = await this.hashingService.verify(
      password,
      user.password,
    );
    if (!isPasswordValid) {
      await this.accountLockService.incrementFailedAttempts(user.id);
      return null;
    }

    await this.accountLockService.resetFailedAttempts(user.id);
    return user;
  }

  async login(
    credentials: LoginCredentials,
    context?: LoginContext,
  ): Promise<LoginResult> {
    // Check if account is locked
    const user = await this.userRepository.findByEmail(credentials.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { locked, unlockTime } = await this.accountLockService.isLocked(
      user.id,
    );
    if (locked) {
      throw new ForbiddenException(
        `Account locked. Try again after ${unlockTime?.toLocaleString('en-US')}`,
      );
    }

    // Validate credentials
    const validatedUser = await this.validateCredentials(
      credentials.email,
      credentials.password,
    );
    if (!validatedUser) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check account status
    if (!validatedUser.isActive) {
      throw new UnauthorizedException('Account inactive');
    }

    if (!validatedUser.isEmailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    // Analyze for security anomalies
    let securityAlerts: any[] = [];
    if (context?.ipAddress && context?.userAgent) {
      try {
        securityAlerts =
          await this.anomalyDetectionService.analyzeLogin(
            validatedUser,
            context.ipAddress,
            context.userAgent,
          );
      } catch (error) {
        this.logger.error(`Anomaly detection error: ${error.message}`);
      }
    }

    // Handle 2FA if enabled
    if (validatedUser.isTwoFactorEnabled) {
      const tfaToken = this.jwtTokenService.generateTwoFactorToken({
        sub: validatedUser.id,
        email: validatedUser.email,
        role: validatedUser.role,
      });

      return {
        accessToken: tfaToken,
        refreshToken: '',
        requiresTwoFactor: true,
        securityAlerts,
        user: {
          id: validatedUser.id,
          email: validatedUser.email,
          firstName: validatedUser.firstName || '',
          lastName: validatedUser.lastName || '',
          role: validatedUser.role,
        },
      };
    }

    // Generate tokens
    const accessToken = this.jwtTokenService.generateAccessToken({
      sub: validatedUser.id,
      email: validatedUser.email,
      role: validatedUser.role,
      isActive: validatedUser.isActive,
    });

    const refreshToken = this.jwtTokenService.generateRefreshToken({
      sub: validatedUser.id,
      email: validatedUser.email,
      role: validatedUser.role,
      isActive: validatedUser.isActive,
    });

    // Save refresh token
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await this.refreshTokenRepository.create({
      token: refreshToken,
      userId: validatedUser.id,
      expiresAt,
      userAgent: context?.userAgent,
      ipAddress: context?.ipAddress,
    });

    return {
      accessToken,
      refreshToken,
      securityAlerts,
      user: {
        id: validatedUser.id,
        email: validatedUser.email,
        firstName: validatedUser.firstName || '',
        lastName: validatedUser.lastName || '',
        role: validatedUser.role,
      },
    };
  }

  async logout(refreshToken: string): Promise<void> {
    await this.refreshTokenRepository.revokeByToken(refreshToken);
  }

  async logoutAll(userId: string): Promise<void> {
    await this.refreshTokenRepository.revokeAllByUserId(userId);
  }
}
