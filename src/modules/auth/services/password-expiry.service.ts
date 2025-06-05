import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import { addDays, differenceInDays, isBefore } from 'date-fns';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEmailService } from 'src/modules/mail/interfaces/email-provider.interface';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class PasswordExpiryService {
    private readonly logger = new Logger(PasswordExpiryService.name);
    private readonly expiryDays: number;
    private readonly warningDays: number;
    private readonly enabled: boolean;

    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        @Inject(INJECTION_TOKENS.EMAIL_SERVICE)
        private readonly emailService: IEmailService,
    ) {
        this.enabled = this.configService.get<boolean>(
            'security.passwordExpiry.enabled',
            true,
        );
        this.expiryDays = this.configService.get<number>(
            'security.passwordExpiry.expiryDays',
            180,
        );
        this.warningDays = this.configService.get<number>(
            'security.passwordExpiry.warningDays',
            14,
        );
    }

    async isPasswordExpired(userId: string): Promise<{
        expired: boolean;
        expiresAt?: Date;
        daysUntilExpiry?: number;
    }> {
        if (!this.enabled) {
            return { expired: false };
        }

        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: {
                passwordExpiresAt: true,
                forcePasswordChange: true,
            },
        });

        if (!user) {
            return { expired: false };
        }

        if (user.forcePasswordChange) {
            return {
                expired: true,
                expiresAt: user.passwordExpiresAt || new Date(),
            };
        }

        if (!user.passwordExpiresAt) {
            const expiresAt = addDays(new Date(), this.expiryDays);
            await this.updatePasswordExpiry(userId, new Date(), expiresAt);
            return {
                expired: false,
                expiresAt,
                daysUntilExpiry: this.expiryDays,
            };
        }

        const now = new Date();
        const expired = isBefore(user.passwordExpiresAt, now);
        const daysUntilExpiry = differenceInDays(user.passwordExpiresAt, now);

        return {
            expired,
            expiresAt: user.passwordExpiresAt,
            daysUntilExpiry: expired ? 0 : daysUntilExpiry,
        };
    }

    async updatePasswordExpiry(
        userId: string,
        changedAt: Date = new Date(),
        expiresAt?: Date,
    ): Promise<void> {
        const calculatedExpiresAt =
            expiresAt || addDays(changedAt, this.expiryDays);

        await this.prisma.user.update({
            where: { id: userId },
            data: {
                passwordChangedAt: changedAt,
                passwordExpiresAt: calculatedExpiresAt,
                forcePasswordChange: false,
                lastPasswordExpiryWarning: null, // Réinitialiser les avertissements
            },
        });

        this.logger.log(
            `Password expiry updated for user ${userId}. Expires at: ${calculatedExpiresAt.toISOString()}`,
        );
    }

    async forcePasswordChange(userId: string): Promise<void> {
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                forcePasswordChange: true,
                passwordExpiresAt: new Date(),
            },
        });

        this.logger.warn(`Password change forced for user: ${userId}`);
    }

    @Cron(CronExpression.EVERY_DAY_AT_9AM)
    async checkPasswordExpiry(): Promise<void> {
        if (!this.enabled) {
            return;
        }

        this.logger.log('Starting password expiry check...');

        try {
            const now = new Date();
            const warningDate = addDays(now, this.warningDays);

            // Trouver les utilisateurs dont le mot de passe va expirer
            const usersToWarn = await this.prisma.user.findMany({
                where: {
                    isActive: true,
                    passwordExpiresAt: {
                        lte: warningDate,
                        gt: now,
                    },
                    OR: [
                        { lastPasswordExpiryWarning: null },
                        {
                            lastPasswordExpiryWarning: {
                                lt: addDays(now, -7), // Rappel hebdomadaire
                            },
                        },
                    ],
                },
            });

            // Envoyer des emails d'avertissement
            for (const user of usersToWarn) {
                if (user.passwordExpiresAt) {
                    const daysUntilExpiry = differenceInDays(
                        user.passwordExpiresAt,
                        now,
                    );

                    await this.sendExpiryWarningEmail(
                        user.email,
                        user.firstName || undefined,
                        daysUntilExpiry,
                    );

                    // Mettre à jour la date du dernier avertissement
                    await this.prisma.user.update({
                        where: { id: user.id },
                        data: { lastPasswordExpiryWarning: now },
                    });
                }
            }

            // Marquer les mots de passe expirés
            const expiredResult = await this.prisma.user.updateMany({
                where: {
                    isActive: true,
                    passwordExpiresAt: { lte: now },
                    forcePasswordChange: false,
                },
                data: { forcePasswordChange: true },
            });

            this.logger.log(
                `Password expiry check completed. ${usersToWarn.length} warnings sent, ${expiredResult.count} passwords expired.`,
            );
        } catch (error) {
            this.logger.error(
                `Error during password expiry check: ${error.message}`,
            );
        }
    }

    private async sendExpiryWarningEmail(
        email: string,
        userName?: string,
        daysUntilExpiry?: number,
    ): Promise<void> {
        try {
            const appName = this.configService.get<string>(
                'app.general.name',
                'Application',
            );
            const frontendUrl = this.configService.get<string>(
                'app.general.frontendUrl',
                '',
            );

            this.logger.log(
                `Password expiry warning sent to ${email} (${daysUntilExpiry} days remaining)`,
            );
        } catch (error) {
            this.logger.error(
                `Failed to send expiry warning to ${email}: ${error.message}`,
            );
        }
    }
}
