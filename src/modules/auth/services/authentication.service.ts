// src/modules/auth/services/authentication.service.ts

import {
    ForbiddenException,
    Inject,
    Injectable,
    Logger,
    UnauthorizedException,
} from '@nestjs/common';
import { User } from 'generated/prisma';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { IHashingService } from '../../../common/interfaces/hashing.interface';
import { AnomalyDetectionService } from '../../../common/services/anomaly-detection.service';
import { IAccountLockService } from '../../users/interfaces/account-lock.interface';
import { IUserRepository } from '../../users/interfaces/user-repository.interface';
import {
    IAuthenticationService,
    LoginContext,
    LoginCredentials,
    LoginResult,
} from '../interfaces/authentication.interface';
import { IRefreshTokenRepository } from '../interfaces/token-repository.interface';
import { IJwtTokenService } from '../interfaces/token-service.interface';
import { PasswordExpiryService } from './password-expiry.service';

@Injectable()
export class AuthenticationService implements IAuthenticationService {
    private readonly logger = new Logger(AuthenticationService.name);

    constructor(
        @Inject(INJECTION_TOKENS.USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
        @Inject(INJECTION_TOKENS.JWT_TOKEN_SERVICE)
        private readonly jwtTokenService: IJwtTokenService,
        @Inject(INJECTION_TOKENS.HASHING_SERVICE)
        private readonly hashingService: IHashingService,
        @Inject(INJECTION_TOKENS.ACCOUNT_LOCK_SERVICE)
        private readonly accountLockService: IAccountLockService,
        @Inject(INJECTION_TOKENS.REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: IRefreshTokenRepository,
        private readonly anomalyDetectionService: AnomalyDetectionService,
        private readonly passwordExpiryService: PasswordExpiryService,
    ) {}

    async login(
        credentials: LoginCredentials,
        context?: LoginContext,
    ): Promise<LoginResult> {
        // 1. Vérifier si l'utilisateur existe
        const user = await this.userRepository.findByEmail(credentials.email);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // 2. Vérifier si le compte est verrouillé
        const { locked, unlockTime } = await this.accountLockService.isLocked(
            user.id,
        );
        if (locked) {
            throw new ForbiddenException(
                `Account locked. Try again after ${unlockTime?.toLocaleString('en-US')}`,
            );
        }

        // 3. Valider les identifiants
        const validatedUser = await this.validateCredentials(
            credentials.email,
            credentials.password,
        );
        if (!validatedUser) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // 4. Vérifier le statut du compte
        if (!validatedUser.isActive) {
            throw new UnauthorizedException('Account inactive');
        }

        if (!validatedUser.isEmailVerified) {
            throw new UnauthorizedException('Email not verified');
        }

        // 5. Analyser les anomalies de sécurité
        let securityAlerts: any[] = [];
        if (context?.ipAddress && context?.userAgent) {
            try {
                securityAlerts =
                    await this.anomalyDetectionService.analyzeLogin(
                        validatedUser,
                        context.ipAddress,
                        context.userAgent,
                    );

                // Log des alertes critiques
                const criticalAlerts = securityAlerts.filter(
                    (alert) =>
                        alert.severity === 'CRITICAL' ||
                        alert.severity === 'HIGH',
                );

                if (criticalAlerts.length > 0) {
                    this.logger.warn(
                        `Security alerts for ${validatedUser.email}:`,
                        {
                            userId: validatedUser.id,
                            alertsCount: criticalAlerts.length,
                            alertTypes: criticalAlerts.map((a) => a.type),
                            ipAddress: context.ipAddress,
                            userAgent: context.userAgent,
                        },
                    );
                }
            } catch (error) {
                this.logger.error(`Anomaly detection error: ${error.message}`);
            }
        }

        // 6. Vérifier l'expiration du mot de passe
        const passwordExpiry =
            await this.passwordExpiryService.isPasswordExpired(
                validatedUser.id,
            );

        // Si le mot de passe a expiré
        if (passwordExpiry.expired) {
            this.logger.warn(
                `Password expired for user: ${validatedUser.email}`,
            );

            // Générer un token spécial avec accès limité
            const limitedAccessToken = this.jwtTokenService.generateAccessToken(
                {
                    sub: validatedUser.id,
                    email: validatedUser.email,
                    role: validatedUser.role,
                    isActive: validatedUser.isActive,
                    forcePasswordChange: true, // Indicateur pour le frontend
                },
            );

            return {
                accessToken: limitedAccessToken,
                refreshToken: '', // Pas de refresh token pour les mots de passe expirés
                requiresPasswordChange: true,
                passwordExpiryInfo: {
                    expired: true,
                    message:
                        'Your password has expired. Please change it to continue.',
                },
                securityAlerts,
                user: {
                    id: validatedUser.id,
                    email: validatedUser.email,
                    firstName: validatedUser.firstName || '',
                    lastName: validatedUser.lastName || '',
                    role: validatedUser.role,
                },
            };
        }

        // 7. Préparer l'avertissement d'expiration si nécessaire
        let passwordExpiryWarning;
        if (
            passwordExpiry.daysUntilExpiry !== undefined &&
            passwordExpiry.daysUntilExpiry <= 14 &&
            passwordExpiry.daysUntilExpiry > 0
        ) {
            passwordExpiryWarning = {
                daysRemaining: passwordExpiry.daysUntilExpiry,
                expiresAt: passwordExpiry.expiresAt,
                message: `Your password will expire in ${passwordExpiry.daysUntilExpiry} day${
                    passwordExpiry.daysUntilExpiry === 1 ? '' : 's'
                }. Please consider changing it soon.`,
            };
        }

        // 8. Gérer l'authentification à deux facteurs si activée
        if (validatedUser.isTwoFactorEnabled) {
            const tfaToken = this.jwtTokenService.generateTwoFactorToken({
                sub: validatedUser.id,
                email: validatedUser.email,
                role: validatedUser.role,
            });

            return {
                accessToken: tfaToken,
                refreshToken: '',
                requiresTwoFactor: true,
                securityAlerts,
                passwordExpiryWarning,
                user: {
                    id: validatedUser.id,
                    email: validatedUser.email,
                    firstName: validatedUser.firstName || '',
                    lastName: validatedUser.lastName || '',
                    role: validatedUser.role,
                },
            };
        }

        // 9. Générer les tokens d'accès et de rafraîchissement
        const accessToken = this.jwtTokenService.generateAccessToken({
            sub: validatedUser.id,
            email: validatedUser.email,
            role: validatedUser.role,
            isActive: validatedUser.isActive,
        });

        const refreshToken = this.jwtTokenService.generateRefreshToken({
            sub: validatedUser.id,
            email: validatedUser.email,
            role: validatedUser.role,
            isActive: validatedUser.isActive,
        });

        // 10. Sauvegarder le refresh token
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 jours

        await this.refreshTokenRepository.create({
            token: refreshToken,
            userId: validatedUser.id,
            expiresAt,
            userAgent: context?.userAgent,
            ipAddress: context?.ipAddress,
        });

        // 11. Mettre à jour la dernière connexion
        await this.userRepository.update(validatedUser.id, {
            lastLoginAt: new Date(),
        });

        // 12. Logger la connexion réussie
        this.logger.log(
            `Successful login for user: ${validatedUser.email} from IP: ${context?.ipAddress || 'unknown'}`,
        );

        // 13. Retourner le résultat complet
        return {
            accessToken,
            refreshToken,
            securityAlerts,
            passwordExpiryWarning,
            user: {
                id: validatedUser.id,
                email: validatedUser.email,
                firstName: validatedUser.firstName || '',
                lastName: validatedUser.lastName || '',
                role: validatedUser.role,
            },
        };
    }

    async validateCredentials(
        email: string,
        password: string,
    ): Promise<User | null> {
        const user = await this.userRepository.findByEmail(email);
        if (!user) {
            return null;
        }

        const isPasswordValid = await this.hashingService.verify(
            password,
            user.password,
        );

        if (!isPasswordValid) {
            await this.accountLockService.incrementFailedAttempts(user.id);
            return null;
        }

        await this.accountLockService.resetFailedAttempts(user.id);
        return user;
    }

    async logout(refreshToken: string): Promise<void> {
        await this.refreshTokenRepository.revokeByToken(refreshToken);
    }

    async logoutAll(userId: string): Promise<void> {
        await this.refreshTokenRepository.revokeAllByUserId(userId);
    }
}
