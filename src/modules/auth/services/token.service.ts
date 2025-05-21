import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { addDays, addMinutes, isPast } from 'date-fns';
import { User } from 'generated/prisma';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class TokenService {
    private readonly logger = new Logger(TokenService.name);

    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly prisma: PrismaService,
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
     * Sauvegarde un token de rafraîchissement en base de données
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

            // Créer un nouveau refresh token
            await this.prisma.refreshToken.create({
                data: {
                    token,
                    expiresAt,
                    userAgent,
                    ipAddress,
                    userId,
                },
            });
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'enregistrement du refresh token: ${error.message}`,
            );
            throw new Error("Erreur lors de l'enregistrement du refresh token");
        }
    }

    /**
     * Vérifie et récupère un token de rafraîchissement
     */
    async getRefreshToken(token: string) {
        const refreshToken = await this.prisma.refreshToken.findUnique({
            where: { token },
            include: { user: true },
        });

        if (!refreshToken) {
            return null;
        }

        // Vérifier si le token n'a pas expiré
        if (isPast(refreshToken.expiresAt) || refreshToken.isRevoked) {
            return null;
        }

        return refreshToken;
    }

    /**
     * Révoque un token de rafraîchissement
     */
    async revokeRefreshToken(token: string): Promise<boolean> {
        try {
            const refreshToken = await this.prisma.refreshToken.findUnique({
                where: { token },
            });

            if (!refreshToken) {
                return false;
            }

            await this.prisma.refreshToken.delete({
                where: { id: refreshToken.id },
            });

            return true;
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
            return true;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la révocation des tokens: ${error.message}`,
            );
            return false;
        }
    }

    /**
     * Crée un token de vérification d'email
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

            // Créer le nouveau token
            await this.prisma.verificationToken.create({
                data: {
                    token,
                    expiresAt,
                    userId,
                },
            });

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
     * Vérifie un token de vérification d'email
     */
    async verifyEmailToken(token: string) {
        const verificationToken =
            await this.prisma.verificationToken.findUnique({
                where: { token },
                include: { user: true },
            });

        if (!verificationToken) {
            return null;
        }

        // Vérifier si le token n'a pas expiré
        if (isPast(verificationToken.expiresAt)) {
            await this.prisma.verificationToken.delete({
                where: { id: verificationToken.id },
            });
            return null;
        }

        return verificationToken;
    }

    /**
     * Crée un token de réinitialisation de mot de passe
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

            // Créer le nouveau token
            await this.prisma.passwordResetToken.create({
                data: {
                    token,
                    expiresAt,
                    userId,
                },
            });

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
     * Vérifie un token de réinitialisation de mot de passe
     */
    async verifyPasswordResetToken(token: string) {
        const passwordResetToken =
            await this.prisma.passwordResetToken.findUnique({
                where: { token },
                include: { user: true },
            });

        if (!passwordResetToken) {
            return null;
        }

        // Vérifier si le token n'a pas expiré
        if (isPast(passwordResetToken.expiresAt)) {
            await this.prisma.passwordResetToken.delete({
                where: { id: passwordResetToken.id },
            });
            return null;
        }

        return passwordResetToken;
    }
}
