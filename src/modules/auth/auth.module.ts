import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

// Import injection tokens
import { INJECTION_TOKENS } from '../../common/constants/injection-tokens';

// Import refactored modules

import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';

// Controllers
import { AuthController } from './auth.controller';

// Services
import { AuthEventsService } from './services/auth-events.service';
import { AuthenticationService } from './services/authentication.service';
import { EmailVerificationService } from './services/email-verification.service';
import { JwtTokenService } from './services/jwt-token.service';
import { PasswordResetTokenService } from './services/password-reset-token.service';
import { PasswordService } from './services/password.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { VerificationTokenService } from './services/verification-token.service';

// Repositories
import { PasswordResetTokenRepository } from './repositories/password-reset-token.repository';
import { RefreshTokenRepository } from './repositories/refresh-token.repository';
import { VerificationTokenRepository } from './repositories/verification-token.repository';

// Guards & Strategies
import { ExceptionModule } from 'src/common/modules/exception.module';
import { SecurityModule } from 'src/common/modules/security.module';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';

// Providers configuration
const authProviders = [
    // Services with interface tokens
    {
        provide: INJECTION_TOKENS.AUTHENTICATION_SERVICE,
        useClass: AuthenticationService,
    },
    {
        provide: INJECTION_TOKENS.PASSWORD_SERVICE,
        useClass: PasswordService,
    },
    {
        provide: INJECTION_TOKENS.JWT_TOKEN_SERVICE,
        useClass: JwtTokenService,
    },
    {
        provide: INJECTION_TOKENS.VERIFICATION_TOKEN_SERVICE,
        useClass: VerificationTokenService,
    },
    {
        provide: INJECTION_TOKENS.PASSWORD_RESET_TOKEN_SERVICE,
        useClass: PasswordResetTokenService,
    },
    {
        provide: INJECTION_TOKENS.TWO_FACTOR_SERVICE,
        useClass: TwoFactorAuthService,
    },
    // Repositories with interface tokens
    {
        provide: INJECTION_TOKENS.REFRESH_TOKEN_REPOSITORY,
        useClass: RefreshTokenRepository,
    },
    {
        provide: INJECTION_TOKENS.VERIFICATION_TOKEN_REPOSITORY,
        useClass: VerificationTokenRepository,
    },
    {
        provide: INJECTION_TOKENS.PASSWORD_RESET_TOKEN_REPOSITORY,
        useClass: PasswordResetTokenRepository,
    },
    // Other services
    EmailVerificationService,
    AuthEventsService,
    JwtStrategy,
    JwtRefreshStrategy,
    // Guards
    {
        provide: APP_GUARD,
        useClass: JwtAuthGuard,
    },
    {
        provide: APP_GUARD,
        useClass: RolesGuard,
    },
];

@Module({
    imports: [
        UsersModule,
        MailModule,
        SecurityModule,
        ExceptionModule,
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('security.jwt.accessSecret'),
                signOptions: {
                    expiresIn: configService.get<string>('security.jwt.accessExpiration'),
                },
            }),
        }),
    ],
    controllers: [AuthController],
    providers: authProviders,
    exports: [
        INJECTION_TOKENS.AUTHENTICATION_SERVICE,
        INJECTION_TOKENS.PASSWORD_SERVICE,
        INJECTION_TOKENS.JWT_TOKEN_SERVICE,
        INJECTION_TOKENS.VERIFICATION_TOKEN_SERVICE,
        INJECTION_TOKENS.PASSWORD_RESET_TOKEN_SERVICE,
        INJECTION_TOKENS.TWO_FACTOR_SERVICE,
    ],
})
export class AuthModule { }