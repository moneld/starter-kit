import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    private readonly logger = new Logger(LocalStrategy.name);

    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email', // Utiliser l'email comme nom d'utilisateur
            passwordField: 'password',
        });
    }

    /**
     * Validation des identifiants pour la stratégie locale
     */
    async validate(email: string, password: string): Promise<any> {
        try {
            const user = await this.authService.validateUser(email, password);

            if (!user) {
                throw new UnauthorizedException('Identifiants invalides');
            }

            return user;
        } catch (error) {
            this.logger.error(
                `Erreur de validation locale: ${(error as Error).message}`,
            );
            throw new UnauthorizedException('Identifiants invalides');
        }
    }
}
