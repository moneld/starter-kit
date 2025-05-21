import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule as PinoLoggerModule } from 'nestjs-pino';
import * as path from 'path';
import * as fs from 'fs';
import * as rfs from 'rotating-file-stream';

@Module({
    imports: [
        PinoLoggerModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => {
                // Récupérer les configurations depuis .env
                const logLevel = configService.get<string>(
                    'app.log.level',
                    'info',
                );
                const logDir = configService.get<string>('app.log.dir', 'logs');
                const maxSize = configService.get<string>('app.log.maxSize', '20m');
                const maxFiles = configService.get<string>('app.log.maxFiles', '14d');

                // S'assurer que le répertoire de logs existe
                const logDirPath = path.isAbsolute(logDir)
                    ? logDir
                    : path.join(process.cwd(), logDir);

                if (!fs.existsSync(logDirPath)) {
                    fs.mkdirSync(logDirPath, { recursive: true });
                }

                const isProduction =
                    configService.get<string>('app.general.nodeEnv') ===
                    'production';

                if (isProduction) {
                    // Analyser la configuration de taille maximale
                    let sizeLimit = '20M'; // Valeur par défaut
                    const sizeMatch = maxSize.match(/^(\d+)([kmg])$/i);
                    if (sizeMatch) {
                        const value = sizeMatch[1];
                        const unit = sizeMatch[2].toUpperCase();
                        sizeLimit = `${value}${unit}`;
                    }

                    // Analyser la configuration de rétention
                    let interval = '1d'; // Valeur par défaut pour la rotation quotidienne
                    let maxRotationFiles = 14; // Nombre de fichiers à conserver par défaut
                    const filesMatch = maxFiles.match(/^(\d+)([dhw])$/i);
                    if (filesMatch) {
                        const value = parseInt(filesMatch[1], 10);
                        const unit = filesMatch[2].toLowerCase();
                        maxRotationFiles = value;

                        // Définir l'intervalle de rotation en fonction de l'unité
                        if (unit === 'd') {
                            interval = '1d'; // Quotidien
                        } else if (unit === 'h') {
                            interval = '1h'; // Horaire
                        } else if (unit === 'w') {
                            interval = '1w'; // Hebdomadaire
                        }
                    }

                    // Fonction de nommage pour les fichiers de logs
                    const filenameGenerator = (time, index) => {
                        if (!time) return 'app.log';

                        const date = time instanceof Date ? time : new Date(time);
                        const year = date.getFullYear();
                        const month = String(date.getMonth() + 1).padStart(2, '0');
                        const day = String(date.getDate()).padStart(2, '0');

                        if (index) {
                            return `app-${year}${month}${day}-${index}.log.gz`;
                        }
                        return `app-${year}${month}${day}.log.gz`;
                    };

                    // Configurer le stream pour les logs généraux
                    const appLogStream = rfs.createStream(filenameGenerator, {
                        size: sizeLimit,         // Taille maximale
                        interval: interval,      // Intervalle de rotation
                        path: logDirPath,        // Chemin du répertoire
                        compress: 'gzip',        // Compression des anciens logs
                        maxFiles: maxRotationFiles, // Nombre maximum de fichiers à conserver
                        teeToStdout: false       // Ne pas dupliquer vers stdout
                    });

                    // Fonction de nommage pour les fichiers d'erreurs
                    const errorFilenameGenerator = (time, index) => {
                        if (!time) return 'error.log';

                        const date = time instanceof Date ? time : new Date(time);
                        const year = date.getFullYear();
                        const month = String(date.getMonth() + 1).padStart(2, '0');
                        const day = String(date.getDate()).padStart(2, '0');

                        if (index) {
                            return `error-${year}${month}${day}-${index}.log.gz`;
                        }
                        return `error-${year}${month}${day}.log.gz`;
                    };

                    // Configurer le stream pour les logs d'erreurs
                    const errorLogStream = rfs.createStream(errorFilenameGenerator, {
                        size: sizeLimit,         // Taille maximale
                        interval: interval,      // Intervalle de rotation
                        path: logDirPath,        // Chemin du répertoire
                        compress: 'gzip',        // Compression des anciens logs
                        maxFiles: maxRotationFiles, // Nombre maximum de fichiers à conserver
                        teeToStdout: false       // Ne pas dupliquer vers stdout
                    });

                    // Créer un filtre pour les logs d'erreurs
                    const errorFilter = (info) => {
                        return info.level === 'error' || info.level === 50;
                    };

                    // Configuration pour la séparation des logs
                    return {
                        pinoHttp: {
                            level: logLevel,
                            // Stream personnalisé avec gestion des niveaux
                            stream: {
                                write: (data) => {
                                    // Écrire dans le stream principal
                                    appLogStream.write(data);

                                    // Analyse JSON pour vérifier si c'est une erreur
                                    try {
                                        const info = JSON.parse(data);
                                        if (info.level === 50 || info.level === 'error') {
                                            errorLogStream.write(data);
                                        }
                                    } catch (e) {
                                        // Fallback en cas d'erreur de parsing JSON
                                        if (data.includes('"level":50') || data.includes('"level":"error"')) {
                                            errorLogStream.write(data);
                                        }
                                    }
                                }
                            },
                            formatters: {
                                level: (label) => ({ level: label }),
                            },
                            redact: {
                                paths: [
                                    'req.headers.authorization',
                                    'req.headers.cookie',
                                    'req.body.password',
                                    'req.body.passwordConfirm',
                                    'req.body.currentPassword',
                                    'req.body.newPassword',
                                    'req.body.newPasswordConfirm',
                                ],
                                remove: true,
                            },
                        },
                    };
                } else {
                    // En développement, utiliser pino-pretty comme avant
                    return {
                        pinoHttp: {
                            level: logLevel,
                            transport: {
                                target: 'pino-pretty',
                                options: {
                                    singleLine: true,
                                    colorize: true,
                                },
                            },
                            formatters: {
                                level: (label) => ({ level: label }),
                            },
                            redact: {
                                paths: [
                                    'req.headers.authorization',
                                    'req.headers.cookie',
                                    'req.body.password',
                                    'req.body.passwordConfirm',
                                    'req.body.currentPassword',
                                    'req.body.newPassword',
                                    'req.body.newPasswordConfirm',
                                ],
                                remove: true,
                            },
                        },
                    };
                }
            },
        }),
    ],
    exports: [PinoLoggerModule],
})
export class LoggingModule {}