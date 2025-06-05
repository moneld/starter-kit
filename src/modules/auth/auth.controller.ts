// src/modules/auth/auth.controller.ts - Version corrigée avec tokens d'injection

import {
    BadRequestException,
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Inject,
    Param,
    Post,
    Query,
    Req,
    UnauthorizedException,
    UseGuards,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { FastifyRequest } from 'fastify';
import { UserRole } from 'generated/prisma';

// Import injection tokens - IMPORTANT!
import { INJECTION_TOKENS } from '../../common/constants/injection-tokens';

// Decorators
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';
import { Roles } from './decorators/roles.decorator';

// DTOs
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { LoginDto } from './dto/login.dto';
import { RecoveryCodeDto } from './dto/recovery-code.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { TwoFactorAuthDto } from './dto/two-factor-auth.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';

// Guards
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';

// Interfaces - pour le typage uniquement
import { IAccountLockService } from '../users/interfaces/account-lock.interface';
import { MessageResponse } from './interfaces/auth-responses.interface';
import { IAuthenticationService } from './interfaces/authentication.interface';
import { IPasswordService } from './interfaces/password-service.interface';
import { IJwtTokenService } from './interfaces/token-service.interface';
import { ITwoFactorService } from './interfaces/two-factor.interface';

// Services
import { Throttle } from '@nestjs/throttler';
import { UsersService } from '../users/users.service';
import { SkipPasswordExpiry } from './decorators/skip-password-expiry.decorator';
import { EmailVerificationService } from './services/email-verification.service';
import { PasswordExpiryService } from './services/password-expiry.service';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(
        // Utilisation des TOKENS d'injection, pas des interfaces directement
        @Inject(INJECTION_TOKENS.AUTHENTICATION_SERVICE)
        private readonly authService: IAuthenticationService,
        @Inject(INJECTION_TOKENS.PASSWORD_SERVICE)
        private readonly passwordService: IPasswordService,
        @Inject(INJECTION_TOKENS.JWT_TOKEN_SERVICE)
        private readonly jwtTokenService: IJwtTokenService,
        @Inject(INJECTION_TOKENS.TWO_FACTOR_SERVICE)
        private readonly twoFactorService: ITwoFactorService,
        private readonly emailVerificationService: EmailVerificationService,
        private readonly usersService: UsersService,
        private readonly passwordExpiryService: PasswordExpiryService,
    ) {}

    // ===== REGISTRATION & VERIFICATION =====

    @Public()
    @Post('register')
    @ApiOperation({ summary: 'Register a new user' })
    @ApiResponse({ status: 201, description: 'User created successfully' })
    @ApiResponse({ status: 400, description: 'Invalid data' })
    @ApiResponse({ status: 409, description: 'Email already exists' })
    async register(@Body() registerDto: RegisterDto): Promise<MessageResponse> {
        // Validate password confirmation
        if (registerDto.password !== registerDto.passwordConfirm) {
            throw new BadRequestException('Passwords do not match');
        }

        // Create user
        const { user, verificationToken } = await this.usersService.create({
            email: registerDto.email,
            password: registerDto.password,
            firstName: registerDto.firstName,
            lastName: registerDto.lastName,
        });

        // Send verification email if needed
        if (verificationToken) {
            await this.emailVerificationService.sendVerificationEmail(
                user.email,
            );
        }

        return {
            message:
                'Registration successful. Please check your email to verify your account.',
        };
    }

    @Public()
    @Get('verify-email')
    @ApiOperation({ summary: 'Verify email address' })
    @ApiResponse({ status: 200, description: 'Email verified successfully' })
    @ApiResponse({ status: 400, description: 'Invalid or expired token' })
    async verifyEmail(@Query('token') token: string): Promise<MessageResponse> {
        await this.emailVerificationService.verifyEmail(token);
        return { message: 'Email verified successfully' };
    }

    @Public()
    @Post('resend-verification-email')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Resend verification email' })
    @ApiResponse({ status: 200, description: 'Verification email sent' })
    async resendVerificationEmail(
        @Body('email') email: string,
    ): Promise<MessageResponse> {
        await this.emailVerificationService.sendVerificationEmail(email);
        return {
            message:
                'If your email is registered, you will receive a verification email.',
        };
    }

    // ===== LOGIN & LOGOUT =====

    @Public()
    @Throttle({ default: { limit: 10, ttl: 60000 } })
    @Post('login')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'User login with security analysis' })
    @ApiResponse({ status: 200, description: 'Login successful' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    @ApiResponse({ status: 403, description: 'Account locked' })
    async login(@Body() loginDto: LoginDto, @Req() req: FastifyRequest) {
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        return this.authService.login(loginDto, { ipAddress, userAgent });
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Logout user' })
    @ApiResponse({ status: 200, description: 'Logout successful' })
    @ApiBearerAuth('access-token')
    async logout(
        @Body('refreshToken') refreshToken: string,
    ): Promise<MessageResponse> {
        await this.authService.logout(refreshToken);
        return { message: 'Logout successful' };
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout-all')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Logout from all sessions' })
    @ApiResponse({ status: 200, description: 'Logged out from all sessions' })
    @ApiBearerAuth('access-token')
    async logoutAll(
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        await this.authService.logoutAll(userId);
        return { message: 'Logged out from all sessions' };
    }

    // ===== TOKEN REFRESH =====

    @Public()
    @Post('refresh-token')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Refresh access token' })
    @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
    @ApiResponse({ status: 401, description: 'Invalid refresh token' })
    async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
        return this.jwtTokenService.refreshTokens(refreshTokenDto.refreshToken);
    }

    // ===== TWO-FACTOR AUTHENTICATION =====

    @UseGuards(JwtAuthGuard)
    @Post('verify-2fa')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Verify 2FA code' })
    @ApiResponse({ status: 200, description: '2FA verification successful' })
    @ApiResponse({ status: 401, description: 'Invalid 2FA code' })
    async verifyTwoFactorAuth(
        @Body() twoFactorAuthDto: TwoFactorAuthDto,
        @CurrentUser() user: any,
    ) {
        const isValid = this.twoFactorService.verifyCode(
            twoFactorAuthDto.twoFactorCode,
            user.twoFactorSecret,
        );

        if (!isValid) {
            throw new UnauthorizedException('Invalid 2FA code');
        }

        // Generate new tokens with 2FA completed
        const accessToken = this.jwtTokenService.generateAccessToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isTwoFactorAuth: true,
        });

        const refreshToken = this.jwtTokenService.generateRefreshToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isTwoFactorAuth: true,
        });

        return { accessToken, refreshToken };
    }

    @UseGuards(JwtAuthGuard)
    @Post('recovery-code')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Login with recovery code' })
    @ApiResponse({ status: 200, description: 'Recovery code valid' })
    @ApiResponse({ status: 401, description: 'Invalid recovery code' })
    async useRecoveryCode(
        @Body() recoveryCodeDto: RecoveryCodeDto,
        @CurrentUser('id') userId: string,
    ) {
        const isValid = await this.twoFactorService.validateRecoveryCode(
            userId,
            recoveryCodeDto.recoveryCode,
        );

        if (!isValid) {
            throw new UnauthorizedException('Invalid recovery code');
        }

        const user = await this.usersService.findById(userId);

        // Generate tokens
        const accessToken = this.jwtTokenService.generateAccessToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isTwoFactorAuth: true,
        });

        const refreshToken = this.jwtTokenService.generateRefreshToken({
            sub: user.id,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            isTwoFactorAuth: true,
        });

        return { accessToken, refreshToken };
    }

    @UseGuards(JwtAuthGuard)
    @Get('2fa/generate')
    @ApiOperation({ summary: 'Generate 2FA secret' })
    @ApiResponse({ status: 200, description: '2FA secret generated' })
    @ApiBearerAuth('access-token')
    async generateTwoFactorSecret(@CurrentUser('email') email: string) {
        return this.twoFactorService.generateSecret(email);
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/enable')
    @ApiOperation({ summary: 'Enable two-factor authentication' })
    @ApiResponse({ status: 200, description: '2FA enabled successfully' })
    @ApiResponse({ status: 401, description: 'Invalid code' })
    @ApiBearerAuth('access-token')
    async enableTwoFactorAuth(
        @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
        @CurrentUser('id') userId: string,
    ) {
        const isValid = this.twoFactorService.verifyCode(
            verifyTwoFactorDto.code,
            verifyTwoFactorDto.secret,
        );

        if (!isValid) {
            throw new UnauthorizedException('Invalid authentication code');
        }

        const recoveryCodes = await this.twoFactorService.enable(
            userId,
            verifyTwoFactorDto.secret,
        );

        return { recoveryCodes };
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/disable')
    @ApiOperation({ summary: 'Disable two-factor authentication' })
    @ApiResponse({ status: 200, description: '2FA disabled successfully' })
    @ApiResponse({ status: 401, description: 'Invalid password' })
    @ApiBearerAuth('access-token')
    async disableTwoFactorAuth(
        @Body('password') password: string,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        // Verify password
        const user = await this.usersService.findById(userId);
        const isPasswordValid = await this.authService.validateCredentials(
            user.email,
            password,
        );

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        await this.twoFactorService.disable(userId);
        return { message: 'Two-factor authentication disabled successfully' };
    }

    @UseGuards(JwtAuthGuard)
    @Post('2fa/recovery-codes')
    @ApiOperation({ summary: 'Regenerate recovery codes' })
    @ApiResponse({ status: 200, description: 'Recovery codes regenerated' })
    @ApiResponse({ status: 401, description: 'Invalid password' })
    @ApiBearerAuth('access-token')
    async regenerateRecoveryCodes(
        @Body('password') password: string,
        @CurrentUser('id') userId: string,
    ) {
        // Verify password
        const user = await this.usersService.findById(userId);
        const isPasswordValid = await this.authService.validateCredentials(
            user.email,
            password,
        );

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        const recoveryCodes =
            await this.twoFactorService.regenerateRecoveryCodes(userId);
        return { recoveryCodes };
    }

    // ===== PASSWORD MANAGEMENT =====

    @Public()
    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Request password reset' })
    @ApiResponse({ status: 200, description: 'Reset email sent' })
    async forgotPassword(
        @Body() forgotPasswordDto: ForgotPasswordDto,
    ): Promise<MessageResponse> {
        await this.passwordService.forgotPassword(forgotPasswordDto.email);
        return {
            message:
                'If your email is registered, you will receive a reset link.',
        };
    }

    @Public()
    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Reset password' })
    @ApiResponse({ status: 200, description: 'Password reset successfully' })
    @ApiResponse({ status: 400, description: 'Invalid or expired token' })
    async resetPassword(
        @Body() resetPasswordDto: ResetPasswordDto,
    ): Promise<MessageResponse> {
        if (resetPasswordDto.password !== resetPasswordDto.passwordConfirm) {
            throw new BadRequestException('Passwords do not match');
        }

        await this.passwordService.resetPassword(
            resetPasswordDto.token,
            resetPasswordDto.password,
        );

        return { message: 'Password reset successfully' };
    }

    @UseGuards(JwtAuthGuard)
    @Post('change-password')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Change password' })
    @ApiResponse({ status: 200, description: 'Password changed successfully' })
    @ApiResponse({ status: 401, description: 'Invalid current password' })
    @ApiBearerAuth('access-token')
    async changePassword(
        @Body() changePasswordDto: ChangePasswordDto,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        if (
            changePasswordDto.newPassword !==
            changePasswordDto.newPasswordConfirm
        ) {
            throw new BadRequestException('New passwords do not match');
        }

        await this.passwordService.changePassword(
            userId,
            changePasswordDto.currentPassword,
            changePasswordDto.newPassword,
        );

        return { message: 'Password changed successfully' };
    }

    // ===== ADMIN ENDPOINTS =====

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/activate')
    @ApiOperation({ summary: 'Activate user account (Admin)' })
    @ApiResponse({ status: 200, description: 'Account activated successfully' })
    @ApiBearerAuth('access-token')
    async activateUser(@Param('id') userId: string): Promise<MessageResponse> {
        await this.usersService.update(userId, { isActive: true });
        return { message: 'User account activated successfully' };
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/deactivate')
    @ApiOperation({ summary: 'Deactivate user account (Admin)' })
    @ApiResponse({
        status: 200,
        description: 'Account deactivated successfully',
    })
    @ApiBearerAuth('access-token')
    async deactivateUser(
        @Param('id') userId: string,
    ): Promise<MessageResponse> {
        await this.usersService.update(userId, { isActive: false });
        return { message: 'User account deactivated successfully' };
    }

    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/unlock')
    @ApiOperation({ summary: 'Unlock user account (Admin)' })
    @ApiResponse({ status: 200, description: 'Account unlocked successfully' })
    @ApiBearerAuth('access-token')
    async unlockUser(
        @Param('id') userId: string,
        // Utilisation du TOKEN d'injection ici aussi
        @Inject(INJECTION_TOKENS.ACCOUNT_LOCK_SERVICE)
        accountLockService: IAccountLockService,
    ): Promise<MessageResponse> {
        await accountLockService.unlockAccount(userId);
        return { message: 'User account unlocked successfully' };
    }

    // ===== SECURITY ENDPOINTS =====

    @UseGuards(JwtAuthGuard)
    @Get('security/sessions')
    @ApiOperation({ summary: 'Get active sessions' })
    @ApiResponse({ status: 200, description: 'Active sessions retrieved' })
    @ApiBearerAuth('access-token')
    async getActiveSessions(@CurrentUser('id') userId: string) {
        // This would need to be implemented in a session service
        return { message: 'Feature not yet implemented' };
    }

    @UseGuards(JwtAuthGuard)
    @Post('security/revoke-session/:sessionId')
    @ApiOperation({ summary: 'Revoke a specific session' })
    @ApiResponse({ status: 200, description: 'Session revoked successfully' })
    @ApiBearerAuth('access-token')
    async revokeSession(
        @Param('sessionId') sessionId: string,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        // This would need to be implemented in a session service
        return { message: 'Feature not yet implemented' };
    }

    @UseGuards(JwtAuthGuard)
    @Get('password-expiry-status')
    @ApiOperation({ summary: 'Check password expiry status' })
    @ApiResponse({ status: 200, description: 'Password expiry status' })
    @ApiBearerAuth('access-token')
    async checkPasswordExpiry(@CurrentUser('id') userId: string) {
        const expiryStatus =
            await this.passwordExpiryService.isPasswordExpired(userId);
        return {
            expired: expiryStatus.expired,
            expiresAt: expiryStatus.expiresAt,
            daysUntilExpiry: expiryStatus.daysUntilExpiry,
            requiresChange: expiryStatus.expired,
        };
    }

    @UseGuards(JwtAuthGuard)
    @Post('change-expired-password')
    @SkipPasswordExpiry() // Permet l'accès même si le mot de passe est expiré
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Change expired password' })
    @ApiResponse({ status: 200, description: 'Password changed successfully' })
    @ApiBearerAuth('access-token')
    async changeExpiredPassword(
        @Body() changePasswordDto: ChangePasswordDto,
        @CurrentUser('id') userId: string,
    ): Promise<MessageResponse> {
        if (
            changePasswordDto.newPassword !==
            changePasswordDto.newPasswordConfirm
        ) {
            throw new BadRequestException('New passwords do not match');
        }

        await this.passwordService.changePassword(
            userId,
            changePasswordDto.currentPassword,
            changePasswordDto.newPassword,
        );

        // Mettre à jour l'expiration du mot de passe
        await this.passwordExpiryService.updatePasswordExpiry(userId);

        return { message: 'Password changed successfully' };
    }

    // Pour les admins : forcer le changement de mot de passe
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
    @Post('users/:id/force-password-change')
    @ApiOperation({ summary: 'Force user to change password (Admin)' })
    @ApiResponse({ status: 200, description: 'Password change forced' })
    @ApiBearerAuth('access-token')
    async forcePasswordChange(
        @Param('id') userId: string,
    ): Promise<MessageResponse> {
        await this.passwordExpiryService.forcePasswordChange(userId);
        return { message: 'User must change password on next login' };
    }
}
