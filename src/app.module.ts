import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CryptoService } from './common/services/crypto.service';
import { appConfig } from './config/app.config';
import { securityConfig } from './config/security.config';
import { PrismaModule } from './modules/prisma/prisma.module';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { MailModule } from './modules/mail/mail.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            load: [appConfig, securityConfig],
        }),
        PrismaModule,
        UsersModule,
        AuthModule,
        MailModule,
    ],
    controllers: [],
    providers: [CryptoService],
})
export class AppModule {}
