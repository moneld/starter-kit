import {
    Inject,
    Injectable,
    Logger,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { IRefreshTokenRepository } from '../interfaces/token-repository.interface';
import { IJwtTokenService } from '../interfaces/token-service.interface';

@Injectable()
export class JwtTokenService implements IJwtTokenService {
    private readonly logger = new Logger(JwtTokenService.name);
    private readonly accessSecret: string;
    private readonly refreshSecret: string;
    private readonly accessExpiration: string;
    private readonly refreshExpiration: string;

    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        @Inject(INJECTION_TOKENS.REFRESH_TOKEN_REPOSITORY)
        private readonly refreshTokenRepository: IRefreshTokenRepository,
    ) {
        this.accessSecret = this.configService.get<string>(
            'security.jwt.accessSecret',
        )!;
        this.refreshSecret = this.configService.get<string>(
            'security.jwt.refreshSecret',
        )!;
        this.accessExpiration = this.configService.get<string>(
            'security.jwt.accessExpiration',
            '15m',
        );
        this.refreshExpiration = this.configService.get<string>(
            'security.jwt.refreshExpiration',
            '7d',
        );
    }

    generateAccessToken(payload: JwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.accessSecret,
            expiresIn: this.accessExpiration,
        });
    }

    generateRefreshToken(payload: JwtPayload): string {
        return this.jwtService.sign(payload, {
            secret: this.refreshSecret,
            expiresIn: this.refreshExpiration,
        });
    }

    generateTwoFactorToken(payload: JwtPayload): string {
        return this.jwtService.sign(
            { ...payload, isTwoFactorAuth: false },
            {
                secret: this.accessSecret,
                expiresIn: '15m',
            },
        );
    }

    verifyToken(token: string, type: 'access' | 'refresh'): JwtPayload {
        try {
            const secret =
                type === 'access' ? this.accessSecret : this.refreshSecret;
            return this.jwtService.verify(token, { secret });
        } catch (error) {
            this.logger.error(`Token verification failed: ${error.message}`);
            throw new UnauthorizedException('Invalid token');
        }
    }

    async refreshTokens(
        refreshToken: string,
    ): Promise<{ accessToken: string; refreshToken: string }> {
        // Verify refresh token
        const payload = this.verifyToken(refreshToken, 'refresh');

        // Check if refresh token exists in database
        const tokenRecord =
            await this.refreshTokenRepository.findByToken(refreshToken);
        if (!tokenRecord) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        // Generate new tokens
        const newAccessToken = this.generateAccessToken({
            sub: payload.sub,
            email: payload.email,
            role: payload.role,
            isActive: payload.isActive,
            isTwoFactorAuth: payload.isTwoFactorAuth,
        });

        const newRefreshToken = this.generateRefreshToken({
            sub: payload.sub,
            email: payload.email,
            role: payload.role,
            isActive: payload.isActive,
            isTwoFactorAuth: payload.isTwoFactorAuth,
        });

        // Revoke old refresh token
        await this.refreshTokenRepository.revokeByToken(refreshToken);

        // Save new refresh token
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        await this.refreshTokenRepository.create({
            token: newRefreshToken,
            userId: payload.sub,
            expiresAt,
            userAgent: tokenRecord.userAgent || undefined,
            ipAddress: tokenRecord.ipAddress || undefined,
        });

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }
}
