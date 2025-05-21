import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  /**
   * Détermine si la requête nécessite une authentification
   */
  canActivate(context: ExecutionContext) {
    // Vérifier si la route est marquée comme publique
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Si la route est publique, autoriser sans vérification
    if (isPublic) {
      return true;
    }

    // Sinon, vérifier l'authentification JWT
    return super.canActivate(context);
  }
}
