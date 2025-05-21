import * as helmet from '@fastify/helmet';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import {
    FastifyAdapter,
    NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { AuthExceptionsFilter } from './modules/auth/filters/auth-exceptions.filter';
import { SecurityHeadersInterceptor } from './modules/auth/interceptors/security-headers.interceptor';

async function bootstrap() {
    // Créer l'application avec Fastify
    const app = await NestFactory.create<NestFastifyApplication>(
        AppModule,
        new FastifyAdapter({ logger: true }),
    );

    // Récupérer la configuration
    const configService = app.get(ConfigService);
    const port = configService.get<number>('app.general.port', 3000);
    const nodeEnv = configService.get<string>(
        'app.general.nodeEnv',
        'development',
    );
    const frontendUrl = configService.get<string>(
        'app.general.frontendUrl',
        '*',
    );
    const appName = configService.get<string>('app.general.name', 'API');

    // Configurer Helmet pour les headers de sécurité
    await app.register(helmet);

    // Configurer CORS
    app.enableCors({
        origin: configService.get<string>('app.cors.origin', '*'),
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        credentials: true,
    });

    // Configurer la validation globale
    app.useGlobalPipes(
        new ValidationPipe({
            whitelist: true, // Supprimer les propriétés non déclarées dans les DTOs
            forbidNonWhitelisted: true, // Rejeter les requêtes avec des propriétés non déclarées
            transform: true, // Transformer les données en DTO typés
            transformOptions: {
                enableImplicitConversion: true, // Convertir automatiquement les types
            },
        }),
    );

    // Ajouter le filtre d'exception global
    app.useGlobalFilters(new AuthExceptionsFilter());

    // Ajouter l'intercepteur de sécurité
    app.useGlobalInterceptors(new SecurityHeadersInterceptor());

    // Configurer Swagger uniquement en développement
    if (nodeEnv !== 'production') {
        const config = new DocumentBuilder()
            .setTitle(`${appName} - Documentation API`)
            .setDescription("Documentation de l'API d'authentification")
            .setVersion('1.0')
            .addBearerAuth(
                {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    name: 'JWT',
                    description: 'Entrez votre token JWT',
                    in: 'header',
                },
                'access-token',
            )
            .build();

        const document = SwaggerModule.createDocument(app, config);
        SwaggerModule.setup('api/docs', app, document);
    }

    // Démarrer le serveur
    await app.listen(port, '0.0.0.0');
    console.log(`Application démarrée sur le port ${port} en mode ${nodeEnv}`);
}

bootstrap();
