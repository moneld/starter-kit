import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { addDays, addMinutes, isPast } from 'date-fns';
import { User } from 'generated/prisma';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { CryptoService } from '../../../common/services/crypto.service';

@Injectable()
export class TokenService {
    private readonly logger = new Logger(TokenService.name);

    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly prisma: PrismaService,
        private readonly cryptoService: CryptoService, // Ajouter CryptoService
    ) {}

    /**
     * Génère un token JWT d'accès pour un utilisateur
     */
    generateAccessToken(user: User, isTwoFactorAuthenticated = false): string {
        const payload: JwtPayload = {
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
        };

        // Ajouter l'info de 2FA si nécessaire
        if (user.isTwoFactorEnabled) {
            payload.isTwoFactorAuth = isTwoFactorAuthenticated;
        }

        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('security.jwt.accessSecret'),
            expiresIn: this.configService.get<string>(
                'security.jwt.accessExpiration',
            ),
        });
    }

    /**
     * Génère un token JWT de rafraîchissement pour un utilisateur
     */
    generateRefreshToken(user: User, isTwoFactorAuthenticated = false): string {
        const payload: JwtPayload = {
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
        };

        // Ajouter l'info de 2FA si nécessaire
        if (user.isTwoFactorEnabled) {
            payload.isTwoFactorAuth = isTwoFactorAuthenticated;
        }

        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>(
                'security.jwt.refreshSecret',
            ),
            expiresIn: this.configService.get<string>(
                'security.jwt.refreshExpiration',
            ),
        });
    }

    /**
     * Génère un token JWT spécial pour l'authentification 2FA
     */
    generateTwoFactorToken(user: User): string {
        const payload: JwtPayload = {
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isTwoFactorAuth: false, // Token spécial pour 2FA en attente
        };

        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('security.jwt.accessSecret'),
            expiresIn: '15m', // Courte durée pour la validation 2FA
        });
    }

    /**
     * Sauvegarde un token de rafraîchissement en base de données (CHIFFRÉ)
     */
    async saveRefreshToken(
        userId: string,
        token: string,
        userAgent?: string,
        ipAddress?: string,
    ): Promise<void> {
        try {
            // Supprimer l'ancien refresh token s'il existe
            await this.prisma.refreshToken.deleteMany({
                where: { userId },
            });

            // Calculer la date d'expiration
            let expiresIn = this.configService.get<string>(
                'security.jwt.refreshExpiration',
                '7d',
            );
            expiresIn = expiresIn.replace(/d$/, ''); // Remove 'd' suffix if present
            const expiresAt = addDays(new Date(), parseInt(expiresIn, 10));

            // CHIFFRER le token avant de le stocker
            const encryptedToken = this.cryptoService.encrypt(token);

            // Créer un nouveau refresh token avec le token chiffré
            await this.prisma.refreshToken.create({
                data: {
                    token: encryptedToken, // Stocker le token chiffré
                    expiresAt,
                    userAgent,
                    ipAddress,
                    userId,
                },
            });

            this.logger.debug(
                `Refresh token chiffré et sauvegardé pour l'utilisateur: ${userId}`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'enregistrement du refresh token: ${error.message}`,
            );
            throw new Error("Erreur lors de l'enregistrement du refresh token");
        }
    }

    /**
     * Vérifie et récupère un token de rafraîchissement (DÉCHIFFREMENT)
     */
    async getRefreshToken(token: string) {
        try {
            // Récupérer tous les refresh tokens de la base pour cet utilisateur
            // (on ne peut pas faire une requête directe car les tokens sont chiffrés)
            const refreshTokens = await this.prisma.refreshToken.findMany({
                where: {
                    expiresAt: { gt: new Date() }, // Seulement les tokens non expirés
                    isRevoked: false,
                },
                include: { user: true },
            });

            // Parcourir les tokens et déchiffrer pour trouver une correspondance
            for (const refreshToken of refreshTokens) {
                try {
                    const decryptedToken = this.cryptoService.decrypt(
                        refreshToken.token,
                    );

                    if (decryptedToken === token) {
                        // Token trouvé et valide
                        if (
                            isPast(refreshToken.expiresAt) ||
                            refreshToken.isRevoked
                        ) {
                            return null;
                        }

                        // Retourner le refresh token avec le token déchiffré pour utilisation
                        return {
                            ...refreshToken,
                            token: decryptedToken, // Retourner le token en clair pour utilisation
                        };
                    }
                } catch (decryptError) {
                    // Ignorer les erreurs de déchiffrement (token avec ancienne clé peut-être)
                    this.logger.debug(
                        `Impossible de déchiffrer un refresh token: ${decryptError.message}`,
                    );
                    continue;
                }
            }

            return null; // Aucun token correspondant trouvé
        } catch (error) {
            this.logger.error(
                `Erreur lors de la récupération du refresh token: ${error.message}`,
            );
            return null;
        }
    }

    /**
     * Révoque un token de rafraîchissement (avec déchiffrement pour trouver le bon)
     */
    async revokeRefreshToken(token: string): Promise<boolean> {
        try {
            // Récupérer tous les refresh tokens non expirés
            const refreshTokens = await this.prisma.refreshToken.findMany({
                where: {
                    expiresAt: { gt: new Date() },
                    isRevoked: false,
                },
            });

            // Trouver le token correspondant en déchiffrant
            for (const refreshToken of refreshTokens) {
                try {
                    const decryptedToken = this.cryptoService.decrypt(
                        refreshToken.token,
                    );

                    if (decryptedToken === token) {
                        // Token trouvé, le supprimer
                        await this.prisma.refreshToken.delete({
                            where: { id: refreshToken.id },
                        });

                        this.logger.debug(
                            `Refresh token révoqué: ${refreshToken.id}`,
                        );
                        return true;
                    }
                } catch (decryptError) {
                    // Ignorer les erreurs de déchiffrement
                    continue;
                }
            }

            return false; // Token non trouvé
        } catch (error) {
            this.logger.error(
                `Erreur lors de la révocation du token: ${error.message}`,
            );
            return false;
        }
    }

    /**
     * Révoque tous les tokens de rafraîchissement d'un utilisateur
     */
    async revokeAllUserTokens(userId: string): Promise<boolean> {
        try {
            await this.prisma.refreshToken.deleteMany({
                where: { userId },
            });

            this.logger.debug(
                `Tous les refresh tokens révoqués pour l'utilisateur: ${userId}`,
            );
            return true;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la révocation des tokens: ${error.message}`,
            );
            return false;
        }
    }

    /**
     * Crée un token de vérification d'email (CHIFFRÉ)
     */
    async createEmailVerificationToken(userId: string): Promise<string> {
        try {
            // Générer un token unique
            const token = uuidv4();
            const expiresAt = addDays(new Date(), 1); // Expire après 24h

            // Supprimer tout token existant
            await this.prisma.verificationToken.deleteMany({
                where: { userId },
            });

            // CHIFFRER le token de vérification
            const encryptedToken = this.cryptoService.encrypt(token);

            // Créer le nouveau token avec chiffrement
            await this.prisma.verificationToken.create({
                data: {
                    token: encryptedToken, // Stocker le token chiffré
                    expiresAt,
                    userId,
                },
            });

            // Retourner le token en clair pour l'envoi par email
            return token;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la création du token de vérification: ${error.message}`,
            );
            throw new Error(
                'Erreur lors de la création du token de vérification',
            );
        }
    }

    /**
     * Vérifie un token de vérification d'email (DÉCHIFFREMENT)
     */
    async verifyEmailToken(token: string) {
        try {
            // Récupérer tous les tokens de vérification non expirés
            const verificationTokens =
                await this.prisma.verificationToken.findMany({
                    where: {
                        expiresAt: { gt: new Date() },
                    },
                    include: { user: true },
                });

            // Parcourir et déchiffrer pour trouver une correspondance
            for (const verificationToken of verificationTokens) {
                try {
                    const decryptedToken = this.cryptoService.decrypt(
                        verificationToken.token,
                    );

                    if (decryptedToken === token) {
                        // Token trouvé et valide
                        if (isPast(verificationToken.expiresAt)) {
                            // Token expiré, le supprimer
                            await this.prisma.verificationToken.delete({
                                where: { id: verificationToken.id },
                            });
                            return null;
                        }

                        return verificationToken;
                    }
                } catch (decryptError) {
                    // Ignorer les erreurs de déchiffrement
                    continue;
                }
            }

            return null; // Aucun token correspondant trouvé
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification du token d'email: ${error.message}`,
            );
            return null;
        }
    }

    /**
     * Crée un token de réinitialisation de mot de passe (CHIFFRÉ)
     */
    async createPasswordResetToken(userId: string): Promise<string> {
        try {
            // Générer un token unique
            const token = uuidv4();
            const expiresAt = addMinutes(new Date(), 60); // Expire après 1h

            // Supprimer tout token existant
            await this.prisma.passwordResetToken.deleteMany({
                where: { userId },
            });

            // CHIFFRER le token de réinitialisation
            const encryptedToken = this.cryptoService.encrypt(token);

            // Créer le nouveau token avec chiffrement
            await this.prisma.passwordResetToken.create({
                data: {
                    token: encryptedToken, // Stocker le token chiffré
                    expiresAt,
                    userId,
                },
            });

            // Retourner le token en clair pour l'envoi par email
            return token;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la création du token de réinitialisation: ${error.message}`,
            );
            throw new Error(
                'Erreur lors de la création du token de réinitialisation',
            );
        }
    }

    /**
     * Vérifie un token de réinitialisation de mot de passe (DÉCHIFFREMENT)
     */
    async verifyPasswordResetToken(token: string) {
        try {
            // Récupérer tous les tokens de réinitialisation non expirés
            const passwordResetTokens =
                await this.prisma.passwordResetToken.findMany({
                    where: {
                        expiresAt: { gt: new Date() },
                    },
                    include: { user: true },
                });

            // Parcourir et déchiffrer pour trouver une correspondance
            for (const passwordResetToken of passwordResetTokens) {
                try {
                    const decryptedToken = this.cryptoService.decrypt(
                        passwordResetToken.token,
                    );

                    if (decryptedToken === token) {
                        // Token trouvé et valide
                        if (isPast(passwordResetToken.expiresAt)) {
                            // Token expiré, le supprimer
                            await this.prisma.passwordResetToken.delete({
                                where: { id: passwordResetToken.id },
                            });
                            return null;
                        }

                        return passwordResetToken;
                    }
                } catch (decryptError) {
                    // Ignorer les erreurs de déchiffrement
                    continue;
                }
            }

            return null; // Aucun token correspondant trouvé
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification du token de réinitialisation: ${error.message}`,
            );
            return null;
        }
    }
}
