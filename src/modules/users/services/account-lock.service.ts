import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { addMinutes } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IAccountLockService } from '../interfaces/account-lock.interface';
import { IUserRepository } from '../interfaces/user-repository.interface';

@Injectable()
export class AccountLockService implements IAccountLockService {
    private readonly logger = new Logger(AccountLockService.name);
    private readonly maxAttempts: number;
    private readonly lockDurationMinutes: number;

    constructor(
        @Inject(INJECTION_TOKENS.USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        private readonly configService: ConfigService,
    ) {
        this.maxAttempts = this.configService.get<number>(
            'security.attemptLockout.maxAttempts',
            5,
        );
        this.lockDurationMinutes = this.parseLockDuration(
            this.configService.get<string>(
                'security.attemptLockout.lockDuration',
                '15m',
            ),
        );
    }

    async incrementFailedAttempts(userId: string): Promise<void> {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            return;
        }

        await this.userRepository.incrementFailedLoginAttempts(userId);

        const updatedAttempts = user.failedLoginAttempts + 1;
        if (updatedAttempts >= this.maxAttempts) {
            await this.lockAccount(userId, this.lockDurationMinutes);
        }

        this.logger.debug(
            `Failed login attempts for ${userId}: ${updatedAttempts}/${this.maxAttempts}`,
        );
    }

    async resetFailedAttempts(userId: string): Promise<void> {
        await this.userRepository.resetFailedLoginAttempts(userId);
    }

    async isLocked(
        userId: string,
    ): Promise<{ locked: boolean; unlockTime?: Date }> {
        const user = await this.userRepository.findById(userId);
        if (!user || !user.lockedUntil) {
            return { locked: false };
        }

        const now = new Date();
        const lockedUntil = new Date(user.lockedUntil);

        if (lockedUntil > now) {
            return { locked: true, unlockTime: lockedUntil };
        }

        // Lock expired, clean up
        await this.unlockAccount(userId);
        return { locked: false };
    }

    async lockAccount(userId: string, durationMinutes?: number): Promise<void> {
        const duration = durationMinutes || this.lockDurationMinutes;
        const lockedUntil = addMinutes(new Date(), duration);

        await this.userRepository.lockAccount(userId, lockedUntil);
        this.logger.warn(
            `Account locked: ${userId} until ${lockedUntil.toISOString()}`,
        );
    }

    async unlockAccount(userId: string): Promise<void> {
        await this.userRepository.unlockAccount(userId);
        this.logger.log(`Account unlocked: ${userId}`);
    }

    private parseLockDuration(duration: string): number {
        const match = duration.match(/^(\d+)([mh])?$/i);
        if (!match) {
            return 15; // default 15 minutes
        }

        const value = parseInt(match[1], 10);
        const unit = match[2]?.toLowerCase() || 'm';

        return unit === 'h' ? value * 60 : value;
    }
}
