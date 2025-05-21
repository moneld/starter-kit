import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { UsersService } from '../../users/users.service';
import { FastifyRequest } from 'fastify';

/**
 * Stratégie pour valider les tokens de rafraîchissement JWT
 */
@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
    Strategy,
    'jwt-refresh',
) {
    constructor(
        private readonly configService: ConfigService,
        private readonly usersService: UsersService,
    ) {
        const secret = configService.get<string>('security.jwt.refreshSecret');
        if (!secret) {
            throw new Error(
                'JWT_REFRESH_SECRET is not defined in environment variables',
            );
        }

        // Utilisez un seul objet de configuration sans StrategyOptions
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: secret,
            ignoreExpiration: false,
            passReqToCallback: true,
        });
    }

    /**
     * Validation du payload JWT de rafraîchissement avec accès à la requête
     */
    async validate(req: FastifyRequest, payload: JwtPayload) {
        // Obtenir le token de rafraîchissement à partir de l'en-tête d'autorisation
        const authHeader = req.headers.authorization;
        const refreshToken = authHeader?.split(' ')[1]; // Extrait le token après "Bearer "

        if (!refreshToken) {
            throw new UnauthorizedException(
                'Token de rafraîchissement manquant',
            );
        }

        try {
            // Vérifier si l'utilisateur existe
            const user = await this.usersService.findById(payload.sub);

            // Vérifier si l'utilisateur est actif
            if (!user.isActive) {
                throw new UnauthorizedException('Compte inactif');
            }

            // Retourner les données utilisateur avec le token de rafraîchissement
            return {
                id: user.id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                refreshToken,
            };
        } catch (error) {
            throw new UnauthorizedException(
                'Token de rafraîchissement invalide',
            );
        }
    }
}
