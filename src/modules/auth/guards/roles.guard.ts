import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from 'generated/prisma';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    /**
     * Vérifie si l'utilisateur a les rôles requis pour accéder à la ressource
     */
    canActivate(context: ExecutionContext): boolean {
        // Récupérer les rôles requis pour l'endpoint
        const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );

        // Si aucun rôle n'est requis, autoriser l'accès
        if (!requiredRoles || requiredRoles.length === 0) {
            return true;
        }

        // Récupérer l'utilisateur de la requête (ajouté par JwtAuthGuard)
        const { user } = context.switchToHttp().getRequest();

        // Si pas d'utilisateur ou pas de rôle, refuser l'accès
        if (!user || !user.role) {
            throw new ForbiddenException(
                'Accès refusé : rôle utilisateur manquant',
            );
        }

        // Vérifier si l'utilisateur a l'un des rôles requis
        const hasRole = requiredRoles.some((role) => user.role === role);

        if (!hasRole) {
            throw new ForbiddenException('Accès refusé : rôle insuffisant');
        }

        return true;
    }
}
