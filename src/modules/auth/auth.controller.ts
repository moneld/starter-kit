import {
    BadRequestException,
    Body,
    ClassSerializerInterceptor,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Logger,
    Param,
    Post,
    Query,
    Req,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { Request } from 'express';
import { UserRole } from 'generated/prisma';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';
import { Roles } from './decorators/roles.decorator';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RecoveryCodeDto } from './dto/recovery-code.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { TwoFactorAuthDto } from './dto/two-factor-auth.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { SecurityHeadersInterceptor } from './interceptors/security-headers.interceptor';
import {
    AuthTokens,
    LoginResponse,
    MessageResponse,
    TwoFactorCodesResponse,
    TwoFactorSecretResponse,
} from './interfaces/auth-responses.interface';
import { AuthEventsService } from './services/auth-events.service';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import {
    AnomalyDetectionService,
    SecurityAlert, SessionMetrics,
} from '../../common/services/anomaly-detection.service';

@ApiTags('Authentification')
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor, SecurityHeadersInterceptor)
export class AuthController {
    private readonly logger = new Logger(AuthController.name);

    constructor(
        private readonly authService: AuthService,
        private readonly authEventsService: AuthEventsService,
        private readonly anomalyDetectionService: AnomalyDetectionService,
    ) {}

    // ===== INSCRIPTION & VERIFICATION =====

    @Public()
    @Post('register')
    @ApiOperation({ summary: "Inscription d'un nouvel utilisateur" })
    @ApiResponse({ status: 201, description: 'Utilisateur créé avec succès' })
    @ApiResponse({ status: 400, description: 'Données invalides' })
    @ApiResponse({ status: 409, description: 'Email déjà utilisé' })
    async register(@Body() registerDto: RegisterDto): Promise<MessageResponse> {
        return this.authService.register(registerDto);
    }

    @Public()
    @Get('verify-email')
    @ApiOperation({ summary: "Vérification d'email" })
    @ApiResponse({ status: 200, description: 'Email vérifié avec succès' })
    @ApiResponse({ status: 400, description: 'Token invalide ou expiré' })
    async verifyEmail(@Query('token') token: string): Promise<MessageResponse> {
        return this.authService.verifyEmail(token);
    }

    @Public()
    @Post('resend-verification-email')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: "Renvoi de l'email de vérification" })
    @ApiResponse({ status: 200, description: 'Email de vérification renvoyé' })
    async resendVerificationEmail(
        @Body('email') email: string,
    ): Promise<MessageResponse> {
        return this.authService.resendVerificationEmail(email);
    }

    // ===== CONNEXION & DECONNEXION =====

    @Public()
    @Throttle({ default: { limit: 10, ttl: 60000 } })
    @Post('login')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Connexion utilisateur avec analyse de sécurité' })
    @ApiResponse({
        status: 200,
        description: 'Connexion réussie avec alertes de sécurité',
        schema: {
            properties: {
                accessToken: { type: 'string' },
                refreshToken: { type: 'string' },
                requiresTwoFactor: { type: 'boolean' },
                securityAlerts: {
                    type: 'array',
                    items: {
                        properties: {
                            type: { type: 'string' },
                            severity: { type: 'string' },
                            details: { type: 'object' },
                        },
                    },
                },
                user: { type: 'object' },
            },
        },
    })
    async login(
        @Body() loginDto: LoginDto,
        @Req() req: Request,
    ): Promise<LoginResponse & { securityAlerts?: SecurityAlert[] }> {
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        const result = await this.authService.login(
            loginDto,
            ipAddress,
            userAgent,
        );

        if (result.securityAlerts && result.securityAlerts.length > 0) {
            this.logger.log(
                `Connexion avec ${result.securityAlerts.length} alertes de sécurité pour ${result.user.email}`,
            );
        }

        if (!result.requiresTwoFactor) {
            await this.authEventsService.onUserLoggedIn(
                result.user as any,
                ipAddress,
                userAgent,
            );
        }

        return result;
    }

    @UseGuards(JwtAuthGuard)
    @SkipThrottle()
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Déconnexion' })
    @ApiResponse({ status: 200, description: 'Déconnexion réussie' })
    @ApiBearerAuth('access-token')
    async logout(
        @Body('refreshToken') refreshToken: string,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        const result = await this.authService.logout(refreshToken);

        // Enregistrer l'événement de déconnexion
        await this.authEventsService.onUserLoggedOut(userId);

        return result;
    }

    @UseGuards(JwtAuthGuard)
    @SkipThrottle()
    @Post('logout-all')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Déconnexion de toutes les sessions' })
    @ApiResponse({
        status: 200,
        description: 'Déconnecté de toutes les sessions',
    })
    @ApiBearerAuth('access-token')
    async logoutAll(
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        return this.authService.logoutAll(userId);
    }

    // ===== REFRESH TOKEN =====

    @Public()
    @Post('refresh-token')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: "Rafraîchissement du token d'accès" })
    @ApiResponse({ status: 200, description: 'Token rafraîchi avec succès' })
    @ApiResponse({
        status: 401,
        description: 'Token de rafraîchissement invalide',
    })
    async refreshToken(
        @Body() refreshTokenDto: RefreshTokenDto,
    ): Promise<AuthTokens> {
        return this.authService.refreshToken(refreshTokenDto);
    }

    // ===== AUTHENTIFICATION A DEUX FACTEURS =====

    @Public()
    @Post('verify-2fa')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Vérification du code 2FA' })
    @ApiResponse({ status: 200, description: 'Vérification 2FA réussie' })
    @ApiResponse({ status: 401, description: 'Code 2FA invalide' })
    async verifyTwoFactorAuth(
        @Body() twoFactorAuthDto: TwoFactorAuthDto,
        @CurrentUser('id') userId: string,
        @Req() req: Request,
    ): Promise<AuthTokens> {
        const result = await this.authService.verifyTwoFactorAuth(
            userId,
            twoFactorAuthDto,
        );

        // Enregistrer l'événement de connexion après 2FA
        const user = await this.authService.getUserById(userId);
        if (user) {
            await this.authEventsService.onUserLoggedIn(
                user,
                req.ip,
                req.headers['user-agent'],
            );
        }

        return result;
    }

    @UseGuards(JwtAuthGuard)
    @Post('recovery-code')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Connexion avec un code de récupération' })
    @ApiResponse({ status: 200, description: 'Code de récupération valide' })
    @ApiResponse({ status: 401, description: 'Code de récupération invalide' })
    async useRecoveryCode(
        @Body() recoveryCodeDto: RecoveryCodeDto,
        @CurrentUser('id') userId: string,
        @Req() req: Request,
    ): Promise<AuthTokens> {
        const result = await this.authService.verifyRecoveryCode(
            userId,
            recoveryCodeDto,
        );

        // Enregistrer l'événement de connexion après utilisation du code de récupération
        const user = await this.authService.getUserById(userId);
        if (user) {
            await this.authEventsService.onUserLoggedIn(
                user,
                req.ip,
                req.headers['user-agent'],
            );
        }

        return result;
    }

    @UseGuards(JwtAuthGuard)
    @Get('2fa/generate')
    @ApiOperation({ summary: "Génération d'un secret 2FA" })
    @ApiResponse({ status: 200, description: 'Secret 2FA généré' })
    @ApiBearerAuth('access-token')
    async generateTwoFactorSecret(
        @CurrentUser('id') userId: string,
    ): Promise<TwoFactorSecretResponse> {
        return this.authService.generateTwoFactorSecret(userId);
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/enable')
    @ApiOperation({
        summary: "Activation de l'authentification à deux facteurs",
    })
    @ApiResponse({ status: 200, description: '2FA activé avec succès' })
    @ApiResponse({ status: 401, description: 'Code invalide' })
    @ApiBearerAuth('access-token')
    async enableTwoFactorAuth(
        @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
        @CurrentUser('id') userId: string,
    ): Promise<TwoFactorCodesResponse> {
        return this.authService.enableTwoFactorAuth(userId, verifyTwoFactorDto);
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/disable')
    @ApiOperation({
        summary: "Désactivation de l'authentification à deux facteurs",
    })
    @ApiResponse({ status: 200, description: '2FA désactivé avec succès' })
    @ApiResponse({ status: 401, description: 'Mot de passe invalide' })
    @ApiBearerAuth('access-token')
    async disableTwoFactorAuth(
        @Body('password') password: string,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        await this.authService.disableTwoFactorAuth(userId, password);
        return {
            message: 'Authentification à deux facteurs désactivée avec succès',
        };
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/recovery-codes')
    @ApiOperation({ summary: 'Régénération des codes de récupération' })
    @ApiResponse({
        status: 200,
        description: 'Codes de récupération régénérés',
    })
    @ApiResponse({ status: 401, description: 'Mot de passe invalide' })
    @ApiBearerAuth('access-token')
    async regenerateRecoveryCodes(
        @Body('password') password: string,
        @CurrentUser('id') userId: string,
    ): Promise<TwoFactorCodesResponse> {
        return this.authService.regenerateRecoveryCodes(userId, password);
    }

    // ===== RÉINITIALISATION DE MOT DE PASSE =====

    @Public()
    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Demande de réinitialisation de mot de passe' })
    @ApiResponse({
        status: 200,
        description: 'Email de réinitialisation envoyé',
    })
    async forgotPassword(
        @Body() forgotPasswordDto: ForgotPasswordDto,
    ): Promise<MessageResponse> {
        return this.authService.forgotPassword(forgotPasswordDto);
    }

    @Public()
    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Réinitialisation du mot de passe' })
    @ApiResponse({ status: 200, description: 'Mot de passe réinitialisé' })
    @ApiResponse({ status: 400, description: 'Token invalide ou expiré' })
    async resetPassword(
        @Body() resetPasswordDto: ResetPasswordDto,
    ): Promise<MessageResponse> {
        return this.authService.resetPassword(resetPasswordDto);
    }

    @UseGuards(JwtAuthGuard)
    @Post('change-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Changement de mot de passe' })
    @ApiResponse({
        status: 200,
        description: 'Mot de passe changé avec succès',
    })
    @ApiResponse({ status: 401, description: 'Mot de passe actuel invalide' })
    @ApiBearerAuth('access-token')
    async changePassword(
        @Body() changePasswordDto: ChangePasswordDto,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        return this.authService.changePassword(userId, changePasswordDto);
    }

    // ===== ADMINISTRATION =====

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/activate')
    @ApiOperation({ summary: 'Activer un compte utilisateur (Admin)' })
    @ApiResponse({ status: 200, description: 'Compte activé avec succès' })
    @ApiResponse({ status: 403, description: 'Accès interdit' })
    @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
    @ApiBearerAuth('access-token')
    async activateUser(@Param('id') userId: string): Promise<MessageResponse> {
        await this.authService.updateUserStatus(userId, true);
        return { message: 'Compte utilisateur activé avec succès' };
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/deactivate')
    @ApiOperation({ summary: 'Désactiver un compte utilisateur (Admin)' })
    @ApiResponse({ status: 200, description: 'Compte désactivé avec succès' })
    @ApiResponse({ status: 403, description: 'Accès interdit' })
    @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
    @ApiBearerAuth('access-token')
    async deactivateUser(
        @Param('id') userId: string,
    ): Promise<MessageResponse> {
        await this.authService.updateUserStatus(userId, false);
        return { message: 'Compte utilisateur désactivé avec succès' };
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/unlock')
    @ApiOperation({ summary: 'Déverrouiller un compte utilisateur (Admin)' })
    @ApiResponse({
        status: 200,
        description: 'Compte déverrouillé avec succès',
    })
    @ApiResponse({ status: 403, description: 'Accès interdit' })
    @ApiResponse({ status: 404, description: 'Utilisateur non trouvé' })
    @ApiBearerAuth('access-token')
    async unlockUser(@Param('id') userId: string): Promise<MessageResponse> {
        await this.authService.unlockUserAccount(userId);
        return { message: 'Compte utilisateur déverrouillé avec succès' };
    }

    @UseGuards(JwtAuthGuard)
    @Get('security/metrics')
    @ApiOperation({
        summary: "Obtenir les métriques de sécurité de l'utilisateur",
    })
    @ApiResponse({ status: 200, description: 'Métriques de sécurité' })
    @ApiBearerAuth('access-token')
    async getUserSecurityMetrics(
        @CurrentUser('id') userId: string,
    ): Promise<SessionMetrics> {
        return await this.anomalyDetectionService.getUserSecurityMetrics(
            userId,
        );
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Get('security/dashboard')
    @ApiOperation({ summary: 'Dashboard de sécurité (Admin)' })
    @ApiResponse({ status: 200, description: 'Dashboard de sécurité' })
    @ApiBearerAuth('access-token')
    async getSecurityDashboard(): Promise<{
        totalActiveSessions: number;
        usersWithMultipleSessions: number;
        newSessionsLast24h: number;
        configuration: any;
    } | null> {
        return await this.anomalyDetectionService.getSecurityDashboard();
    }

    @UseGuards(JwtAuthGuard)
    @Post('security/revoke-suspicious-sessions')
    @ApiOperation({ summary: 'Révoquer les sessions suspectes' })
    @ApiResponse({ status: 200, description: 'Sessions suspectes révoquées' })
    @ApiBearerAuth('access-token')
    async revokeSuspiciousSessions(
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        try {
            const metrics =
                await this.anomalyDetectionService.getUserSecurityMetrics(
                    userId,
                );

            if (metrics.suspiciousScore > 30) {
                await this.authService.logoutAll(userId);

                return {
                    message: `Sessions suspectes révoquées. Score de risque: ${metrics.suspiciousScore}`,
                };
            }

            return {
                message: 'Aucune session suspecte détectée',
            };
        } catch (error) {
            this.logger.error(
                `Erreur révocation sessions suspectes: ${error.message}`,
            );
            throw new BadRequestException(
                'Erreur lors de la révocation des sessions',
            );
        }
    }
}
