import { registerAs } from '@nestjs/config';

export const appConfig = registerAs('app', () => ({
    // Application
    general: {
        nodeEnv: process.env.NODE_ENV,
        name: process.env.APP_NAME,
        port: parseInt(process.env.PORT || '3000', 10),
        frontendUrl: process.env.FRONTEND_URL,
    },

    // Cors
    cors: {
        origin: process.env.CORS_ORIGIN,
    },
    // Logging
    log: {
        level: process.env.LOG_LEVEL,
        dir: process.env.LOG_DIR,
        maxSize: process.env.LOG_MAX_SIZE,
        maxFiles: process.env.LOG_MAX_FILES,
    },

    //  Mail
    mail: {
        host: process.env.MAIL_HOST,
        port: parseInt(process.env.MAIL_PORT || '465', 10),
        encryption: process.env.MAIL_ENCRYPTION,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASSWORD,
        },
        from: process.env.MAIL_FROM,
    },
}));
