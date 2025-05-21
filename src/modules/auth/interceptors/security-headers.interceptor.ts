import {
    CallHandler,
    ExecutionContext,
    Injectable,
    NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

/**
 * Intercepteur pour ajouter des en-têtes de sécurité aux réponses
 */
@Injectable()
export class SecurityHeadersInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        return next.handle().pipe(
            tap(() => {
                const response = context.switchToHttp().getResponse();

                // En-têtes de sécurité
                response.header('X-Content-Type-Options', 'nosniff');
                response.header('X-Frame-Options', 'DENY');
                response.header('X-XSS-Protection', '1; mode=block');
                response.header(
                    'Strict-Transport-Security',
                    'max-age=31536000; includeSubDomains',
                );

                // Empêcher la mise en cache des réponses d'authentification
                response.header(
                    'Cache-Control',
                    'no-store, no-cache, must-revalidate, proxy-revalidate',
                );
                response.header('Pragma', 'no-cache');
                response.header('Expires', '0');
                response.header('Surrogate-Control', 'no-store');
            }),
        );
    }
}
