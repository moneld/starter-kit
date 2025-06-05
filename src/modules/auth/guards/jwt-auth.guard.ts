import {
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SKIP_PASSWORD_EXPIRY_KEY } from '../decorators/skip-password-expiry.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    constructor(private reflector: Reflector) {
        super();
    }

    async canActivate(context: ExecutionContext) {
        // Vérifier si la route est publique
        const isPublic = this.reflector.getAllAndOverride<boolean>(
            IS_PUBLIC_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (isPublic) {
            return true;
        }

        // Vérifier l'authentification JWT
        const isAuthenticated = await super.canActivate(context);
        if (!isAuthenticated) {
            return false;
        }

        // Vérifier si on doit ignorer l'expiration du mot de passe
        const skipPasswordExpiry = this.reflector.getAllAndOverride<boolean>(
            SKIP_PASSWORD_EXPIRY_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (skipPasswordExpiry) {
            return true;
        }

        // Vérifier l'expiration du mot de passe
        const request = context.switchToHttp().getRequest();
        const user = request.user;

        if (user && user.forcePasswordChange) {
            throw new UnauthorizedException(
                'Password expired. Please change your password.',
            );
        }

        return true;
    }
}
