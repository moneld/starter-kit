import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    Logger,
    UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RecoveryCodeDto } from './dto/recovery-code.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { TwoFactorAuthDto } from './dto/two-factor-auth.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { AuthEventsService } from './services/auth-events.service';
import { TokenService } from './services/token.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        private readonly prisma: PrismaService,
        private readonly usersService: UsersService,
        private readonly tokenService: TokenService,
        private readonly twoFactorAuthService: TwoFactorAuthService,
        private readonly authEventsService: AuthEventsService,
    ) {}

    /**
     * Enregistre un nouvel utilisateur
     */
    async register(registerDto: RegisterDto): Promise<{ message: string }> {
        // Vérifier que les mots de passe correspondent
        if (registerDto.password !== registerDto.passwordConfirm) {
            throw new BadRequestException(
                'Les mots de passe ne correspondent pas',
            );
        }

        try {
            // Créer un nouvel utilisateur
            const { user, verificationToken } = await this.usersService.create({
                email: registerDto.email,
                password: registerDto.password,
                firstName: registerDto.firstName,
                lastName: registerDto.lastName,
            });

            // Déclencher l'événement d'inscription
            if (verificationToken) {
                await this.authEventsService.onUserRegistered(
                    user,
                    verificationToken,
                );
            }

            return {
                message:
                    'Inscription réussie. Veuillez vérifier votre email pour activer votre compte.',
            };
        } catch (error) {
            this.logger.error(`Erreur lors de l'inscription: ${error.message}`);
            throw error; // L'erreur sera gérée par le filtre d'exception
        }
    }

    /**
     * Connecte un utilisateur
     */
    async login(loginDto: LoginDto): Promise<{
        accessToken: string;
        refreshToken: string;
        requiresTwoFactor?: boolean;
        user: {
            id: string;
            email: string;
            firstName: string;
            lastName: string;
            role: string;
        };
    }> {
        try {
            // Trouver l'utilisateur par email
            const user = await this.usersService.findByEmail(loginDto.email);

            // Vérifier si le compte est verrouillé
            const { locked, unlockTime } =
                await this.usersService.isAccountLocked(user.id);
            if (locked) {
                throw new ForbiddenException(
                    `Compte verrouillé. Réessayez après ${unlockTime ? unlockTime.toLocaleString() : 'un certain temps'}`,
                );
            }

            // Vérifier si le compte est actif et vérifié
            if (!user.isActive) {
                throw new UnauthorizedException('Compte inactif');
            }

            if (!user.isEmailVerified) {
                throw new UnauthorizedException('Email non vérifié');
            }

            // Vérifier le mot de passe
            const isPasswordValid = await this.validatePassword(
                loginDto.password,
                user.password,
            );

            if (!isPasswordValid) {
                // Incrémenter le compteur d'échecs de connexion
                await this.usersService.incrementLoginAttempts(user.id);

                // Déclencher l'événement d'échec de connexion
                await this.authEventsService.onLoginFailed(user.email);

                throw new UnauthorizedException('Identifiants invalides');
            }

            // Réinitialiser le compteur d'échecs de connexion
            await this.usersService.resetLoginAttempts(user.id);

            // Déclencher l'événement de connexion réussie
            await this.authEventsService.onUserLoggedIn(user);

            // Vérifier si l'authentification à deux facteurs est activée
            if (user.isTwoFactorEnabled) {
                // Générer un token JWT spécial pour l'authentification 2FA
                const tfaToken = this.tokenService.generateTwoFactorToken(user);

                return {
                    accessToken: tfaToken,
                    refreshToken: '', // Pas de refresh token avant la 2FA complète
                    requiresTwoFactor: true,
                    user: {
                        id: user.id,
                        email: user.email,
                        firstName: user.firstName || '', // Assurez-vous que ce n'est jamais null
                        lastName: user.lastName || '', // Assurez-vous que ce n'est jamais null
                        role: user.role,
                    },
                };
            }

            // Générer les tokens
            const accessToken = this.tokenService.generateAccessToken(user);
            const refreshToken = this.tokenService.generateRefreshToken(user);

            // Enregistrer le refresh token
            await this.tokenService.saveRefreshToken(user.id, refreshToken);

            return {
                accessToken,
                refreshToken,
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.firstName || '', // Assurez-vous que ce n'est jamais null
                    lastName: user.lastName || '', // Assurez-vous que ce n'est jamais null
                    role: user.role,
                }
            };
        } catch (error) {
            this.logger.error(`Erreur lors de la connexion: ${error.message}`);
            throw error; // L'erreur sera gérée par le filtre d'exception
        }
    }

    /**
     * Valide un code d'authentification à deux facteurs
     */
    async verifyTwoFactorAuth(
        userId: string,
        twoFactorAuthDto: TwoFactorAuthDto,
    ): Promise<{
        accessToken: string;
        refreshToken: string;
    }> {
        try {
            const user = await this.usersService.findById(userId);

            if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
                throw new BadRequestException(
                    "L'authentification à deux facteurs n'est pas activée",
                );
            }

            // Déchiffrer le secret 2FA et vérifier le code
            const isCodeValid = this.twoFactorAuthService.verifyCode(
                twoFactorAuthDto.twoFactorCode,
                user.twoFactorSecret,
            );

            if (!isCodeValid) {
                throw new UnauthorizedException(
                    "Code d'authentification à deux facteurs invalide",
                );
            }

            // Générer les tokens avec 2FA complète
            const accessToken = this.tokenService.generateAccessToken(
                user,
                true,
            );
            const refreshToken = this.tokenService.generateRefreshToken(
                user,
                true,
            );

            // Enregistrer le refresh token
            await this.tokenService.saveRefreshToken(user.id, refreshToken);

            return { accessToken, refreshToken };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification 2FA: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Valide un code de récupération d'urgence
     */
    async verifyRecoveryCode(
        userId: string,
        recoveryCodeDto: RecoveryCodeDto,
    ): Promise<{
        accessToken: string;
        refreshToken: string;
    }> {
        try {
            const user = await this.usersService.findById(userId);

            if (!user.isTwoFactorEnabled) {
                throw new BadRequestException(
                    "L'authentification à deux facteurs n'est pas activée",
                );
            }

            // Valider le code de récupération
            const isCodeValid =
                await this.twoFactorAuthService.validateRecoveryCode(
                    user,
                    recoveryCodeDto.recoveryCode,
                );

            if (!isCodeValid) {
                throw new UnauthorizedException(
                    'Code de récupération invalide',
                );
            }

            // Générer les tokens avec 2FA complète
            const accessToken = this.tokenService.generateAccessToken(
                user,
                true,
            );
            const refreshToken = this.tokenService.generateRefreshToken(
                user,
                true,
            );

            // Enregistrer le refresh token
            await this.tokenService.saveRefreshToken(user.id, refreshToken);

            return { accessToken, refreshToken };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la validation du code de récupération: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Active l'authentification à deux facteurs
     */
    async generateTwoFactorSecret(userId: string): Promise<{
        secret: string;
        qrCodeUrl: string;
    }> {
        try {
            const user = await this.usersService.findById(userId);
            return await this.twoFactorAuthService.generateSecret(user.email);
        } catch (error) {
            this.logger.error(
                `Erreur lors de la génération du secret 2FA: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Vérifie et active l'authentification à deux facteurs
     */
    async enableTwoFactorAuth(
        userId: string,
        verifyTwoFactorDto: VerifyTwoFactorDto,
    ): Promise<{
        recoveryCodes: string[];
    }> {
        try {
            const { secret, code } = verifyTwoFactorDto;

            // Vérifier si le code est valide
            const isCodeValid = this.twoFactorAuthService.verifyCode(
                code,
                secret,
            );

            if (!isCodeValid) {
                throw new UnauthorizedException(
                    "Code d'authentification invalide",
                );
            }

            // Activer 2FA et générer des codes de récupération
            const recoveryCodes = await this.twoFactorAuthService.enable(
                userId,
                secret,
            );

            // Récupérer l'utilisateur pour l'événement
            const user = await this.usersService.findById(userId);

            // Déclencher l'événement d'activation 2FA
            await this.authEventsService.onTwoFactorEnabled(user);

            return { recoveryCodes };
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'activation de la 2FA: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Désactive l'authentification à deux facteurs
     */
    async disableTwoFactorAuth(
        userId: string,
        password: string,
    ): Promise<void> {
        try {
            const user = await this.usersService.findById(userId);

            // Vérifier le mot de passe
            const isPasswordValid = await this.validatePassword(
                password,
                user.password,
            );
            if (!isPasswordValid) {
                throw new UnauthorizedException('Mot de passe invalide');
            }

            // Désactiver 2FA
            await this.twoFactorAuthService.disable(userId);

            // Déclencher l'événement de désactivation 2FA
            await this.authEventsService.onTwoFactorDisabled(user);
        } catch (error) {
            this.logger.error(
                `Erreur lors de la désactivation de la 2FA: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Régénère les codes de récupération
     */
    async regenerateRecoveryCodes(
        userId: string,
        password: string,
    ): Promise<{
        recoveryCodes: string[];
    }> {
        try {
            const user = await this.usersService.findById(userId);

            // Vérifier le mot de passe
            const isPasswordValid = await this.validatePassword(
                password,
                user.password,
            );
            if (!isPasswordValid) {
                throw new UnauthorizedException('Mot de passe invalide');
            }

            // Régénérer les codes de récupération
            const recoveryCodes =
                await this.twoFactorAuthService.regenerateRecoveryCodes(userId);

            return { recoveryCodes };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la régénération des codes: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Rafraîchit le token d'accès avec un token de rafraîchissement
     */
    async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<{
        accessToken: string;
        refreshToken: string;
    }> {
        try {
            const { refreshToken } = refreshTokenDto;

            // Vérifier si le token existe et est valide
            const tokenRecord =
                await this.tokenService.getRefreshToken(refreshToken);

            if (!tokenRecord) {
                throw new UnauthorizedException(
                    'Token de rafraîchissement invalide ou expiré',
                );
            }

            // Générer de nouveaux tokens
            const accessToken = this.tokenService.generateAccessToken(
                tokenRecord.user,
                tokenRecord.user.isTwoFactorEnabled, // Si 2FA est activé, on considère qu'il a déjà été validé
            );
            const newRefreshToken = this.tokenService.generateRefreshToken(
                tokenRecord.user,
                tokenRecord.user.isTwoFactorEnabled,
            );

            // Révoquer l'ancien token et enregistrer le nouveau
          //  await this.tokenService.revokeRefreshToken(refreshToken);
            await this.tokenService.saveRefreshToken(
                tokenRecord.user.id,
                newRefreshToken,
                tokenRecord.userAgent || undefined, // Conversion en undefined si null
                tokenRecord.ipAddress || undefined // Conversion en undefined si null
            );

            return {
                accessToken,
                refreshToken: newRefreshToken,
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors du rafraîchissement du token: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Déconnecte un utilisateur en révoquant son token de rafraîchissement
     */
    async logout(refreshToken: string): Promise<{ message: string }> {
        try {
            const revoked =
                await this.tokenService.revokeRefreshToken(refreshToken);

            return {
                message: revoked
                    ? 'Déconnexion réussie'
                    : 'Aucune session active trouvée',
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la déconnexion: ${error.message}`,
            );
            return { message: 'Déconnexion réussie' }; // Toujours renvoyer un succès
        }
    }

    /**
     * Déconnecte un utilisateur de toutes ses sessions
     */
    async logoutAll(userId: string): Promise<{ message: string }> {
        try {
            await this.tokenService.revokeAllUserTokens(userId);

            // Déclencher l'événement de déconnexion
            await this.authEventsService.onUserLoggedOut(userId);

            return { message: 'Déconnecté de toutes les sessions' };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la déconnexion globale: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Demande de réinitialisation de mot de passe
     */
    async forgotPassword(
        forgotPasswordDto: ForgotPasswordDto,
    ): Promise<{ message: string }> {
        try {
            const { email } = forgotPasswordDto;

            // Vérifier si l'utilisateur existe
            let user;
            try {
                user = await this.usersService.findByEmail(email);
            } catch (error) {
                // Ne pas divulguer si l'email existe ou non pour des raisons de sécurité
                return {
                    message:
                        'Si votre email est enregistré, vous recevrez un lien de réinitialisation.',
                };
            }

            // Créer un token de réinitialisation
            const resetToken = await this.tokenService.createPasswordResetToken(
                user.id,
            );

            // Déclencher l'événement de demande de réinitialisation
            await this.authEventsService.onPasswordResetRequested(
                user,
                resetToken,
            );

            return {
                message:
                    'Si votre email est enregistré, vous recevrez un lien de réinitialisation.',
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la demande de réinitialisation: ${error.message}`,
            );
            return {
                message:
                    'Si votre email est enregistré, vous recevrez un lien de réinitialisation.',
            };
        }
    }

    /**
     * Réinitialise le mot de passe avec un token
     */
    async resetPassword(
        resetPasswordDto: ResetPasswordDto,
    ): Promise<{ message: string }> {
        // Vérifier que les mots de passe correspondent
        if (resetPasswordDto.password !== resetPasswordDto.passwordConfirm) {
            throw new BadRequestException(
                'Les mots de passe ne correspondent pas',
            );
        }

        try {
            // Vérifier le token de réinitialisation
            const resetTokenRecord =
                await this.tokenService.verifyPasswordResetToken(
                    resetPasswordDto.token,
                );

            if (!resetTokenRecord) {
                throw new BadRequestException(
                    'Token de réinitialisation invalide ou expiré',
                );
            }

            // Mettre à jour le mot de passe
            await this.usersService.changePassword(
                resetTokenRecord.userId,
                resetPasswordDto.password,
            );

            // Supprimer le token de réinitialisation après utilisation
            await this.prisma.passwordResetToken.delete({
                where: { id: resetTokenRecord.id },
            });

            // Révoquer tous les tokens de rafraîchissement
            await this.tokenService.revokeAllUserTokens(
                resetTokenRecord.userId,
            );

            return { message: 'Mot de passe réinitialisé avec succès' };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la réinitialisation: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Change le mot de passe d'un utilisateur connecté
     */
    async changePassword(
        userId: string,
        changePasswordDto: ChangePasswordDto,
    ): Promise<{
        message: string;
    }> {
        // Vérifier que les mots de passe correspondent
        if (
            changePasswordDto.newPassword !==
            changePasswordDto.newPasswordConfirm
        ) {
            throw new BadRequestException(
                'Les nouveaux mots de passe ne correspondent pas',
            );
        }

        try {
            const user = await this.usersService.findById(userId);

            // Vérifier l'ancien mot de passe
            const isPasswordValid = await this.validatePassword(
                changePasswordDto.currentPassword,
                user.password,
            );

            if (!isPasswordValid) {
                throw new UnauthorizedException('Mot de passe actuel invalide');
            }

            // Changer le mot de passe
            await this.usersService.changePassword(
                userId,
                changePasswordDto.newPassword,
            );

            // Révoquer tous les tokens de rafraîchissement
            await this.tokenService.revokeAllUserTokens(userId);

            return { message: 'Mot de passe changé avec succès' };
        } catch (error) {
            this.logger.error(
                `Erreur lors du changement de mot de passe: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Vérifie un email avec un token
     */
    async verifyEmail(token: string): Promise<{ message: string }> {
        try {
            // Vérifier le token de vérification
            const verificationToken =
                await this.tokenService.verifyEmailToken(token);

            if (!verificationToken) {
                throw new BadRequestException(
                    'Token de vérification invalide ou expiré',
                );
            }

            // Marquer l'email comme vérifié et activer le compte
            await this.usersService.update(verificationToken.userId, {
                isEmailVerified: true,
                isActive: true,
            });

            // Supprimer le token de vérification
            await this.prisma.verificationToken.delete({
                where: { id: verificationToken.id },
            });

            // Déclencher l'événement de vérification d'email
            await this.authEventsService.onEmailVerified(
                verificationToken.user,
            );

            return { message: 'Email vérifié avec succès' };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification d'email: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Renvoie un email de vérification
     */
    async resendVerificationEmail(email: string): Promise<{ message: string }> {
        try {
            // Trouver l'utilisateur
            let user;
            try {
                user = await this.usersService.findByEmail(email);
            } catch (error) {
                // Ne pas divulguer si l'email existe ou non
                return {
                    message:
                        'Si votre email est enregistré, vous recevrez un email de vérification.',
                };
            }

            // Vérifier si l'email est déjà vérifié
            if (user.isEmailVerified) {
                return { message: 'Votre email est déjà vérifié' };
            }

            // Créer un nouveau token de vérification
            const verificationToken =
                await this.tokenService.createEmailVerificationToken(user.id);

            // Déclencher l'événement d'inscription pour envoyer l'email
            await this.authEventsService.onUserRegistered(
                user,
                verificationToken,
            );

            return {
                message:
                    'Email de vérification envoyé. Veuillez vérifier votre boîte de réception.',
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'envoi de l'email de vérification: ${error.message}`,
            );
            return {
                message:
                    'Si votre email est enregistré, vous recevrez un email de vérification.',
            };
        }
    }

    /**
     * Valide les identifiants utilisateur (utilisé par la stratégie locale)
     */
    async validateUser(email: string, password: string): Promise<any> {
        try {
            // Trouver l'utilisateur par email
            const user = await this.usersService.findByEmail(email);

            // Vérifier si le compte est verrouillé
            const { locked } = await this.usersService.isAccountLocked(user.id);
            if (locked) {
                return null;
            }

            // Vérifier si le compte est actif et vérifié
            if (!user.isActive || !user.isEmailVerified) {
                return null;
            }

            // Vérifier le mot de passe
            const isPasswordValid = await this.validatePassword(
                password,
                user.password,
            );

            if (!isPasswordValid) {
                // Incrémenter le compteur d'échecs de connexion
                await this.usersService.incrementLoginAttempts(user.id);

                // Déclencher l'événement d'échec de connexion
                await this.authEventsService.onLoginFailed(user.email);

                return null;
            }

            // Réinitialiser le compteur d'échecs de connexion
            await this.usersService.resetLoginAttempts(user.id);

            // Retourner l'utilisateur sans le mot de passe
            const { password: _, ...result } = user;
            return result;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la validation utilisateur: ${error.message}`,
            );
            return null;
        }
    }

    /**
     * Récupère un utilisateur par son ID
     */
    async getUserById(userId: string) {
        try {
            return await this.usersService.findById(userId);
        } catch (error) {
            this.logger.error(
                `Erreur lors de la récupération de l'utilisateur: ${error.message}`,
            );
            return null;
        }
    }

    /**
     * Mise à jour du statut d'un utilisateur (activation/désactivation)
     */
    async updateUserStatus(userId: string, isActive: boolean): Promise<void> {
        try {
            await this.usersService.update(userId, { isActive });

            // Si le compte est désactivé, révoquer tous les tokens
            if (!isActive) {
                await this.tokenService.revokeAllUserTokens(userId);
            }
        } catch (error) {
            this.logger.error(
                `Erreur lors de la mise à jour du statut utilisateur: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Déverrouillage d'un compte utilisateur
     */
    async unlockUserAccount(userId: string): Promise<void> {
        try {
            await this.usersService.update(userId, {
                failedLoginAttempts: 0,
                lockedUntil: null,
            });
        } catch (error) {
            this.logger.error(
                `Erreur lors du déverrouillage du compte: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Valide un mot de passe avec Argon2
     */
    private async validatePassword(
        plainPassword: string,
        hashedPassword: string,
    ): Promise<boolean> {
        try {
            return await argon2.verify(hashedPassword, plainPassword);
        } catch (error) {
            this.logger.error(
                `Erreur lors de la validation du mot de passe: ${error.message}`,
            );
            return false;
        }
    }
}
