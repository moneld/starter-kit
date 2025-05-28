import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule } from '@nestjs/throttler';
import { ExceptionModule } from './common/modules/exception.module';
import { LoggingModule } from './common/modules/logging.module';
import { SecurityModule } from './common/modules/security.module';
import { appConfig } from './config/app.config';
import { securityConfig } from './config/security.config';
import { AuthModule } from './modules/auth/auth.module';
import { MailModule } from './modules/mail/mail.module';
import { PrismaModule } from './modules/prisma/prisma.module';
import { UsersModule } from './modules/users/users.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            load: [appConfig, securityConfig],
        }),
        ThrottlerModule.forRootAsync({
            imports: [ConfigModule],
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
            inject: [ConfigService],
        }),
        ScheduleModule.forRoot(),
        MailModule,
        LoggingModule,
        SecurityModule,
        ExceptionModule,
        PrismaModule,
        UsersModule,
        AuthModule,

    ],
    controllers: [],
    providers: [],
})
export class AppModule { }
