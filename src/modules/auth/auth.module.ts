import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { MailModule } from '../mail/mail.module';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { AuthEventsService } from './services/auth-events.service';
import { TokenService } from './services/token.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { CryptoService } from '../../common/services/crypto.service';

@Module({
    imports: [
        UsersModule,
        MailModule,
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('security.jwt.accessSecret'),
                signOptions: {
                    expiresIn: configService.get<string>(
                        'security.jwt.accessExpiration',
                    ),
                },
            }),
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthService,
        TokenService,
        TwoFactorAuthService,
        AuthEventsService,
        JwtStrategy,
        JwtRefreshStrategy,
        CryptoService,
        {
            provide: APP_GUARD,
            useClass: JwtAuthGuard,
        },
        {
            provide: APP_GUARD,
            useClass: RolesGuard,
        },
    ],
    exports: [AuthService, TokenService],
})
export class AuthModule {}
