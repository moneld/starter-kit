import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private readonly configService: ConfigService,
        private readonly usersService: UsersService,
    ) {
        const secret = configService.get<string>('security.jwt.accessSecret');
        if (!secret) {
            throw new Error('JWT_ACCESS_SECRET is not defined in environment variables');
        }

        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: secret, // Fournir une valeur non-undefined
        });
    }

    /**
     * Validation du payload JWT
     */
    async validate(payload: JwtPayload) {
        try {
            // Vérifier si l'utilisateur existe toujours
            const user = await this.usersService.findById(payload.sub);

            // Vérifier si l'utilisateur est actif
            if (!user.isActive) {
                throw new UnauthorizedException('Compte inactif');
            }

            // Pour les utilisateurs avec 2FA activée, vérifier si 2FA a été complétée
            if (user.isTwoFactorEnabled && !payload.isTwoFactorAuth) {
                throw new UnauthorizedException('Authentification à deux facteurs requise');
            }

            // Retourner les informations utilisateur à attacher à la requête
            return {
                id: user.id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
            };
        } catch (error) {
            throw new UnauthorizedException('Token JWT invalide');
        }
    }
}