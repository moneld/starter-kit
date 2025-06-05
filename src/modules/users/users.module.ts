import { Module } from '@nestjs/common';
import { SecurityModule } from 'src/common/modules/security.module';
import { INJECTION_TOKENS } from '../../common/constants/injection-tokens';
import { UserRepository } from './repositories/user.repository';
import { AccountLockService } from './services/account-lock.service';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

const userProviders = [
    UsersService,
    {
        provide: INJECTION_TOKENS.USER_REPOSITORY,
        useClass: UserRepository,
    },
    {
        provide: INJECTION_TOKENS.ACCOUNT_LOCK_SERVICE,
        useClass: AccountLockService,
    },
];

@Module({
    imports: [SecurityModule],
    controllers: [UsersController],
    providers: userProviders,
    exports: [
        UsersService,
        INJECTION_TOKENS.USER_REPOSITORY,
        INJECTION_TOKENS.ACCOUNT_LOCK_SERVICE,
    ],
})
export class UsersModule {}
