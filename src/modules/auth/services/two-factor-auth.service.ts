import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { User } from 'generated/prisma';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import { CryptoService } from '../../../common/services/crypto.service';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class TwoFactorAuthService {
    private readonly logger = new Logger(TwoFactorAuthService.name);

    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        private readonly cryptoService: CryptoService,
    ) {
        // Configurer les options d'authentificateur
        authenticator.options = {
            step: 30, // Période de validité en secondes
            window: 1, // Fenêtre de tolérance pour le délai
        };
    }

    /**
     * Génère un secret pour l'authentification à deux facteurs
     */
    async generateSecret(email: string): Promise<{
        secret: string;
        qrCodeUrl: string;
    }> {
        try {
            // Générer un nouveau secret
            const appName = this.configService.get<string>(
                'security.tfa.appName',
                'MyApp',
            );
            const secret = authenticator.generateSecret();

            // Générer l'URL OTP Auth pour les applications d'authentification
            const otpAuthUrl = authenticator.keyuri(email, appName, secret);

            // Générer le QR code
            const qrCodeUrl = await qrcode.toDataURL(otpAuthUrl);

            return {
                secret,
                qrCodeUrl,
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la génération du secret 2FA: ${error.message}`,
            );
            throw new Error('Erreur lors de la génération du secret 2FA');
        }
    }

    /**
     * Vérifie un code d'authentification à deux facteurs
     */
    verifyCode(token: string, secret: string): boolean {
        try {
            return authenticator.verify({
                token,
                secret,
            });
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification du code 2FA: ${error.message}`,
            );
            return false;
        }
    }

    /**
     * Active l'authentification à deux facteurs pour un utilisateur
     */
    async enable(userId: string, secret: string): Promise<string[]> {
        try {
            // Générer des codes de récupération
            const recoveryCodes = await this.generateRecoveryCodes();

            // Chiffrer le secret et les codes de récupération
            const encryptedSecret = this.cryptoService.encrypt(secret);
            const encryptedRecoveryCodes = this.cryptoService.encrypt(
                JSON.stringify(recoveryCodes),
            );

            // Activer 2FA pour l'utilisateur
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    isTwoFactorEnabled: true,
                    twoFactorSecret: encryptedSecret,
                    twoFactorRecoveryCodes: encryptedRecoveryCodes,
                },
            });

            return recoveryCodes;
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'activation de la 2FA: ${error.message}`,
            );
            throw new Error(
                "Erreur lors de l'activation de l'authentification à deux facteurs",
            );
        }
    }

    /**
     * Désactive l'authentification à deux facteurs pour un utilisateur
     */
    async disable(userId: string): Promise<void> {
        try {
            // Désactiver 2FA
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    isTwoFactorEnabled: false,
                    twoFactorSecret: null,
                    twoFactorRecoveryCodes: null,
                },
            });
        } catch (error) {
            this.logger.error(
                `Erreur lors de la désactivation de la 2FA: ${error.message}`,
            );
            throw new Error(
                "Erreur lors de la désactivation de l'authentification à deux facteurs",
            );
        }
    }

    /**
     * Vérifie si un code de récupération est valide et le consomme
     */
    async validateRecoveryCode(
        user: User,
        recoveryCode: string,
    ): Promise<boolean> {
        try {
            // Vérifier si la 2FA est activée
            if (!user.isTwoFactorEnabled || !user.twoFactorRecoveryCodes) {
                return false;
            }

            // Déchiffrer les codes de récupération
            const decryptedCodes = this.cryptoService.decrypt(
                user.twoFactorRecoveryCodes,
            );
            const recoveryCodes = JSON.parse(decryptedCodes) as string[];

            // Vérifier si le code de récupération est valide
            const codeIndex = recoveryCodes.indexOf(recoveryCode);
            if (codeIndex === -1) {
                return false;
            }

            // Supprimer le code utilisé
            recoveryCodes.splice(codeIndex, 1);

            // Mettre à jour les codes de récupération
            const updatedEncryptedCodes = this.cryptoService.encrypt(
                JSON.stringify(recoveryCodes),
            );
            await this.prisma.user.update({
                where: { id: user.id },
                data: { twoFactorRecoveryCodes: updatedEncryptedCodes },
            });

            return true;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la validation du code de récupération: ${error.message}`,
            );
            return false;
        }
    }

    /**
     * Génère de nouveaux codes de récupération pour un utilisateur
     */
    async regenerateRecoveryCodes(userId: string): Promise<string[]> {
        try {
            // Vérifier si la 2FA est activée
            const user = await this.prisma.user.findUnique({
                where: { id: userId },
                select: { isTwoFactorEnabled: true },
            });

            if (!user || !user.isTwoFactorEnabled) {
                throw new Error(
                    "L'authentification à deux facteurs n'est pas activée",
                );
            }

            // Générer de nouveaux codes de récupération
            const recoveryCodes = await this.generateRecoveryCodes();
            const encryptedRecoveryCodes = this.cryptoService.encrypt(
                JSON.stringify(recoveryCodes),
            );

            // Mettre à jour les codes de récupération
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    twoFactorRecoveryCodes: encryptedRecoveryCodes,
                },
            });

            return recoveryCodes;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la régénération des codes de récupération: ${error.message}`,
            );
            throw new Error(
                'Erreur lors de la régénération des codes de récupération',
            );
        }
    }

    /**
     * Génère des codes de récupération pour 2FA
     */
    private async generateRecoveryCodes(): Promise<string[]> {
        const recoveryCodesCount = parseInt(
            this.configService.get<string>(
                'security.tfa.recoveryCodesCount',
                '8',
            ),
        );
        const recoveryCodeLength = parseInt(
            this.configService.get<string>(
                'security.tfa.recoveryCodeLength',
                '10',
            ),
        );

        const recoveryCodes: string[] = [];
        for (let i = 0; i < recoveryCodesCount; i++) {
            recoveryCodes.push(
                this.cryptoService.generateSecureToken(recoveryCodeLength),
            );
        }

        return recoveryCodes;
    }
}
