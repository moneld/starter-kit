import { Inject, Injectable, Logger } from '@nestjs/common';
import { User } from 'generated/prisma';

import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IEmailService } from 'src/modules/mail/interfaces/email-provider.interface';

@Injectable()
export class AuthEventsService {
    private readonly logger = new Logger(AuthEventsService.name);

    constructor(
        @Inject(INJECTION_TOKENS.EMAIL_SERVICE)
        private readonly emailService: IEmailService,
    ) {}

    /**
     * Gère l'événement d'inscription utilisateur
     */
    async onUserRegistered(
        user: User,
        verificationToken: string,
    ): Promise<void> {
        this.logger.log(`Utilisateur inscrit: ${user.email}`);

        try {
            // Envoyer l'email de vérification
            const emailSent = await this.emailService.sendVerificationEmail(
                user.email,
                verificationToken,
                user.firstName || undefined, // Corriger le problème de type null vs undefined
            );

            if (!emailSent) {
                this.logger.error(
                    `Échec d'envoi de l'email de vérification: ${user.email}`,
                );
            }
        } catch (error) {
            this.logger.error(
                `Erreur lors du traitement de l'inscription: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Gère l'événement de vérification d'email
     */
    async onEmailVerified(user: User): Promise<void> {
        this.logger.log(`Email vérifié: ${user.email}`);

        try {
            // Envoyer l'email de bienvenue
            const emailSent = await this.emailService.sendWelcomeEmail(
                user.email,
                user.firstName || undefined, // Corriger le problème de type null vs undefined
            );

            if (!emailSent) {
                this.logger.error(
                    `Échec d'envoi de l'email de bienvenue: ${user.email}`,
                );
            }
        } catch (error) {
            this.logger.error(
                `Erreur lors du traitement de la vérification d'email: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Gère l'événement de demande de réinitialisation de mot de passe
     */
    async onPasswordResetRequested(
        user: User,
        resetToken: string,
    ): Promise<void> {
        this.logger.log(
            `Demande de réinitialisation de mot de passe: ${user.email}`,
        );

        try {
            // Envoyer l'email de réinitialisation
            const emailSent = await this.emailService.sendPasswordResetEmail(
                user.email,
                resetToken,
                user.firstName || undefined, // Corriger le problème de type null vs undefined
            );

            if (!emailSent) {
                this.logger.error(
                    `Échec d'envoi de l'email de réinitialisation: ${user.email}`,
                );
            }
        } catch (error) {
            this.logger.error(
                `Erreur lors de la demande de réinitialisation: ${(error as Error).message}`,
            );
        }
    }

    /**
     * Gère l'événement de connexion utilisateur
     */
    async onUserLoggedIn(
        user: User,
        ipAddress?: string,
        userAgent?: string,
    ): Promise<void> {
        this.logger.log(
            `Connexion utilisateur: ${user.email}, IP: ${ipAddress || 'inconnue'}`,
        );

        // Ici, vous pourriez implémenter des notifications de sécurité
        // Par exemple, envoyer un email pour informer d'une nouvelle connexion
        // si elle a lieu depuis un nouvel appareil ou une nouvelle localisation
    }

    /**
     * Gère l'événement de déconnexion utilisateur
     */
    async onUserLoggedOut(userId: string): Promise<void> {
        this.logger.log(`Déconnexion utilisateur: ${userId}`);
    }

    /**
     * Gère l'événement d'activation de 2FA
     */
    async onTwoFactorEnabled(user: User): Promise<void> {
        this.logger.log(`2FA activé: ${user.email}`);

        // Vous pourriez envoyer un email de notification pour informer
        // l'utilisateur que l'authentification à deux facteurs a été activée
    }

    /**
     * Gère l'événement de désactivation de 2FA
     */
    async onTwoFactorDisabled(user: User): Promise<void> {
        this.logger.log(`2FA désactivé: ${user.email}`);

        // Vous pourriez envoyer un email de notification pour informer
        // l'utilisateur que l'authentification à deux facteurs a été désactivée
    }

    /**
     * Gère l'événement d'échec de connexion
     */
    async onLoginFailed(email: string, ipAddress?: string): Promise<void> {
        this.logger.warn(
            `Échec de connexion: ${email}, IP: ${ipAddress || 'inconnue'}`,
        );

        // Ici, vous pourriez implémenter des notifications en cas de multiples échecs
    }

    /**
     * Gère l'événement de verrouillage de compte
     */
    async onAccountLocked(user: User, unlockTime: Date): Promise<void> {
        this.logger.warn(
            `Compte verrouillé: ${user.email}, déverrouillage à: ${unlockTime.toISOString()}`,
        );

        // Envoyer un email pour informer l'utilisateur que son compte a été verrouillé
        // et quand il sera déverrouillé
    }
}
