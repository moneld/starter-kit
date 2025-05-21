import {
    ArgumentsHost,
    BadRequestException,
    Catch,
    ConflictException,
    ExceptionFilter,
    ForbiddenException,
    HttpException,
    HttpStatus,
    Logger,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { Prisma } from 'generated/prisma';

/**
 * Filtre d'exception global pour gérer toutes les erreurs de l'application
 */
@Catch()
export class AuthExceptionsFilter implements ExceptionFilter {
    private readonly logger = new Logger(AuthExceptionsFilter.name);

    catch(exception: unknown, host: ArgumentsHost): void {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<FastifyReply>();
        const request = ctx.getRequest<FastifyRequest>();

        // Extraire les informations de base de la requête pour la journalisation
        const path = request.url;
        const method = request.method;
        const requestId = request.id;
        const ip = request.ip || 'unknown';
        const userAgent = request.headers['user-agent'] || 'unknown';
        // Modifier cette ligne pour éviter l'erreur TS2339
        const userId = (request as any).user?.id || 'anonymous';

        // Variables pour la réponse
        let status: HttpStatus;
        let message: string | string[];
        let error: string;

        // ==== Traitement en fonction du type d'exception ====

        // 1. Exceptions HTTP NestJS
        if (exception instanceof HttpException) {
            status = exception.getStatus();
            const exceptionResponse = exception.getResponse();

            if (typeof exceptionResponse === 'object') {
                message =
                    (exceptionResponse as any).message || exception.message;
                error = (exceptionResponse as any).error || 'Error';
            } else {
                message = exceptionResponse;
                error = 'Error';
            }

            // Journaliser différemment selon le type d'erreur
            if (exception instanceof UnauthorizedException) {
                this.logger.warn(
                    `[Auth] Unauthorized: ${path} (${requestId}) - User: ${userId}, IP: ${ip}`,
                );
            } else if (exception instanceof ForbiddenException) {
                this.logger.warn(
                    `[Auth] Forbidden: ${path} (${requestId}) - User: ${userId}, IP: ${ip}`,
                );
            } else if (exception instanceof BadRequestException) {
                this.logger.warn(
                    `[Auth] Bad request: ${path} (${requestId}) - ${JSON.stringify(message)}`,
                );
            } else if (exception instanceof ConflictException) {
                this.logger.warn(
                    `[Auth] Conflict: ${path} (${requestId}) - ${JSON.stringify(message)}`,
                );
            } else if (exception instanceof NotFoundException) {
                this.logger.warn(`[Auth] Not found: ${path} (${requestId})`);
            } else {
                this.logger.error(
                    `[Auth] HTTP exception: ${exception.message}`,
                    exception.stack,
                );
            }
        }
        // 2. Erreurs JWT de Passport
        else if (
            exception instanceof Error &&
            (exception.name === 'JsonWebTokenError' ||
                exception.name === 'TokenExpiredError' ||
                exception.name === 'NotBeforeError')
        ) {
            status = HttpStatus.UNAUTHORIZED;

            if (exception.name === 'TokenExpiredError') {
                message = 'Session expirée, veuillez vous reconnecter';
                error = 'TokenExpired';
                this.logger.debug(
                    `[Auth] Token expired: ${path} (${requestId}) - User: ${userId}`,
                );
            } else if (exception.name === 'NotBeforeError') {
                message = 'Token pas encore valide';
                error = 'TokenNotActive';
                this.logger.warn(
                    `[Auth] Token not yet active: ${path} (${requestId}) - User: ${userId}`,
                );
            } else {
                message = 'Session invalide, veuillez vous reconnecter';
                error = 'InvalidToken';
                this.logger.warn(
                    `[Auth] Invalid token: ${path} (${requestId}) - User: ${userId}, IP: ${ip}`,
                );
            }
        }
        // 3. Erreurs Prisma
        else if (
            exception instanceof Prisma.PrismaClientKnownRequestError ||
            exception instanceof Prisma.PrismaClientUnknownRequestError ||
            exception instanceof Prisma.PrismaClientRustPanicError ||
            exception instanceof Prisma.PrismaClientInitializationError ||
            exception instanceof Prisma.PrismaClientValidationError
        ) {
            const prismaError = exception as Error & {
                code?: string;
                meta?: Record<string, any>;
            };

            // Mapper l'erreur Prisma à un code HTTP et un message approprié
            const { httpStatus, userMessage, logLevel } =
                this.handlePrismaError(prismaError);

            status = httpStatus;
            message = userMessage;
            error = `Database Error${prismaError.code ? ` (${prismaError.code})` : ''}`;

            // Journaliser selon le niveau de gravité
            const logMessage = `[Auth] Database error: ${prismaError.message}, Code: ${prismaError.code || 'None'}, Path: ${path} (${requestId})`;

            if (logLevel === 'error') {
                this.logger.error(logMessage, prismaError.stack);
            } else if (logLevel === 'warn') {
                this.logger.warn(logMessage);
            } else {
                this.logger.debug(logMessage);
            }
        }
        // 4. Erreurs de Passport
        else if (
            exception instanceof Error &&
            exception.name === 'AuthenticationError'
        ) {
            status = HttpStatus.UNAUTHORIZED;
            message = exception.message || "Échec d'authentification";
            error = 'AuthenticationFailed';

            this.logger.warn(
                `[Auth] Passport authentication failed: ${path} (${requestId}) - IP: ${ip}`,
            );
        }
        // 5. Erreurs JavaScript standard
        else if (exception instanceof Error) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = exception.message || 'Une erreur interne est survenue';
            error = exception.name || 'InternalServerError';

            this.logger.error(
                `[Auth] Unhandled error: ${exception.message}, Path: ${path} (${requestId})`,
                exception.stack,
            );
        }
        // 6. Autres types d'erreurs
        else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = 'Une erreur inconnue est survenue';
            error = 'UnknownError';

            this.logger.error(
                `[Auth] Unknown error type: ${JSON.stringify(exception)}, Path: ${path} (${requestId})`,
            );
        }

        // ==== Sanitisation des erreurs en production ====
        if (process.env.NODE_ENV === 'production') {
            // Ne pas exposer les détails des erreurs internes en production
            if (status === HttpStatus.INTERNAL_SERVER_ERROR) {
                message = 'Une erreur interne est survenue';
                error = 'InternalServerError';
            }

            // Ne pas exposer les détails des erreurs de validation de la base de données
            if (
                error.includes('Database Error') &&
                status === HttpStatus.BAD_REQUEST
            ) {
                message = 'Données invalides';
                error = 'ValidationError';
            }
        }

        // ==== Construction de la réponse d'erreur ====
        const errorResponse = {
            statusCode: status,
            message: message,
            error: error,
            timestamp: new Date().toISOString(),
            path: path,
            requestId: requestId,
        };

        // Envoyer la réponse
        response.status(status).send(errorResponse);
    }

    /**
     * Gère les erreurs Prisma en les convertissant en messages d'erreur compréhensibles
     */
    private handlePrismaError(
        prismaError: Error & { code?: string; meta?: Record<string, any> },
    ): {
        httpStatus: HttpStatus;
        userMessage: string;
        logLevel: 'error' | 'warn' | 'debug';
    } {
        // Par défaut
        let httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        let userMessage = "Une erreur est survenue lors de l'accès aux données";
        let logLevel: 'error' | 'warn' | 'debug' = 'error';

        // Traiter selon le code d'erreur Prisma
        if (prismaError.code) {
            switch (prismaError.code) {
                // Violation de contrainte d'unicité
                case 'P2002':
                    httpStatus = HttpStatus.CONFLICT;
                    const target = prismaError.meta?.target;
                    if (Array.isArray(target) && target.length > 0) {
                        const fields = target.join(', ');
                        userMessage = `Un enregistrement avec ce(s) ${fields} existe déjà`;
                    } else {
                        userMessage = `Un enregistrement avec ces données existe déjà`;
                    }
                    logLevel = 'warn';
                    break;

                // Enregistrement non trouvé
                case 'P2025':
                    httpStatus = HttpStatus.NOT_FOUND;
                    userMessage = `L'enregistrement demandé n'existe pas`;
                    logLevel = 'debug';
                    break;

                // Violation de contrainte de relation
                case 'P2003':
                    httpStatus = HttpStatus.BAD_REQUEST;
                    userMessage = `L'opération a échoué car elle fait référence à des données qui n'existent pas`;
                    logLevel = 'warn';
                    break;

                // Valeur nulle non autorisée
                case 'P2011':
                    httpStatus = HttpStatus.BAD_REQUEST;
                    const nullField = prismaError.meta?.target;
                    userMessage = `Le champ '${nullField || 'requis'}' ne peut pas être vide`;
                    logLevel = 'debug';
                    break;

                // Erreurs de validation diverses
                case 'P2000': // Valeur trop longue
                case 'P2001': // Type invalide
                case 'P2005': // Valeur invalide
                case 'P2006': // Format invalide
                case 'P2007': // Validation échouée
                case 'P2008': // Erreur de syntaxe
                case 'P2009': // Erreur de requête
                case 'P2010': // Erreur de format brut
                case 'P2012': // Champ requis manquant
                case 'P2013': // Types incompatibles
                case 'P2014': // Erreur de relation
                case 'P2015': // Relation introuvable
                case 'P2016': // Requête invalide
                case 'P2017': // Relation requise
                case 'P2018': // Relation requise connectée
                case 'P2019': // Problème d'entrée
                case 'P2020': // Problème de valeur
                    httpStatus = HttpStatus.BAD_REQUEST;
                    userMessage = `Données invalides: ${prismaError.message}`;
                    logLevel = 'debug';
                    break;

                // Problèmes de structure de base de données
                case 'P2021': // Table n'existe pas
                case 'P2022': // Colonne n'existe pas
                case 'P2023': // Inconsistance
                    httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
                    userMessage = `Problème de configuration de la base de données`;
                    logLevel = 'error';
                    break;

                // Problèmes de connexion
                case 'P2024': // Timeout
                    httpStatus = HttpStatus.SERVICE_UNAVAILABLE;
                    userMessage = `Le service de base de données est temporairement indisponible`;
                    logLevel = 'error';
                    break;

                // Autres erreurs
                default:
                    httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
                    userMessage = `Une erreur de base de données est survenue`;
                    logLevel = 'error';
                    break;
            }
        } else if (prismaError instanceof Prisma.PrismaClientValidationError) {
            // Erreurs de validation qui n'ont pas de code spécifique
            httpStatus = HttpStatus.BAD_REQUEST;
            userMessage = `Données invalides`;
            logLevel = 'debug';
        } else if (
            prismaError instanceof Prisma.PrismaClientInitializationError
        ) {
            // Erreurs d'initialisation
            httpStatus = HttpStatus.SERVICE_UNAVAILABLE;
            userMessage = `Le service de base de données est temporairement indisponible`;
            logLevel = 'error';
        } else if (prismaError instanceof Prisma.PrismaClientRustPanicError) {
            // Erreurs critiques
            httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
            userMessage = `Une erreur critique est survenue`;
            logLevel = 'error';
        }

        return { httpStatus, userMessage, logLevel };
    }
}
