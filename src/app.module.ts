// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { CryptoService } from './common/services/crypto.service';
import { appConfig } from './config/app.config';
import { securityConfig } from './config/security.config';
import { PrismaModule } from './modules/prisma/prisma.module';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { MailModule } from './modules/mail/mail.module';
import { ScheduleModule } from '@nestjs/schedule';
import { KeyRotationService } from './common/services/key-rotation.service';
import { LoggingModule } from './common/modules/logging.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            load: [appConfig, securityConfig],
        }),
        ThrottlerModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                throttlers: [
                    {
                        ttl: config.get<number>(
                            'security.rateLimit.ttl',
                            60000,
                        ),
                        limit: config.get<number>('security.rateLimit.max', 5),
                    },
                ],
            }),
        }),
        ScheduleModule.forRoot(),
        LoggingModule,
        PrismaModule,
        UsersModule,
        AuthModule,
        MailModule,
    ],
    controllers: [],
    providers: [
        CryptoService,
        KeyRotationService,
        {
            provide: APP_GUARD,
            useClass: ThrottlerGuard,
        },
    ],
})
export class AppModule {}
