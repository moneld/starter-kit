import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { FastifyRequest } from 'fastify';

/**
 * Décorateur pour obtenir l'utilisateur courant depuis la requête Fastify
 * Usage: @CurrentUser() user: User ou @CurrentUser('id') userId: string
 */
export const CurrentUser = createParamDecorator(
    (data: string | undefined, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest<FastifyRequest>();

        // Récupérer l'utilisateur depuis la requête
        // Avec Fastify, l'utilisateur est généralement disponible dans request.user
        const user = (request as any).user;

        // Si pas d'utilisateur dans la requête, retourne null
        if (!user) {
            return null;
        }

        // Si une propriété spécifique est demandée, la retourner
        return data ? user[data] : user;
    },
);