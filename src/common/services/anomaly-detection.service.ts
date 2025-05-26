import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../modules/prisma/prisma.service';
import { MailService } from '../../modules/mail/mail.service';
import * as geoip from 'geoip-lite';
import { User } from 'generated/prisma';

// ✅ EXPORT DES INTERFACES POUR RÉSOUDRE LES ERREURS TS4053
export interface SecurityAlert {
    userId: string;
    type:
        | 'SUSPICIOUS_LOGIN'
        | 'MULTIPLE_SESSIONS'
        | 'LOCATION_CHANGE'
        | 'UNUSUAL_ACTIVITY'
        | 'BRUTE_FORCE';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: Record<string, any>;
    timestamp: Date;
}

export interface SessionMetrics {
    userId: string;
    activeSessionCount: number;
    countriesCount: number;
    deviceTypesCount: number;
    suspiciousScore: number;
    lastLoginFromNewLocation: boolean;
    lastLoginFromNewDevice: boolean;
    recentLoginAttempts: number;
    averageSessionDuration: number;
}

export interface SecurityConfig {
    maxConcurrentSessions: number;
    alertEmailEnabled: boolean;
    autoRevokeEnabled: boolean;
    geoTrackingEnabled: boolean;
}

@Injectable()
export class AnomalyDetectionService {
    private readonly logger = new Logger(AnomalyDetectionService.name);
    private securityConfig: SecurityConfig;

    constructor(
        private readonly prisma: PrismaService,
        private readonly mailService: MailService,
        private readonly configService: ConfigService,
    ) {
        this.securityConfig = {
            maxConcurrentSessions: parseInt(
                this.configService.get<string>(
                    'security.session.maxConcurrentSessions',
                    '3',
                ),
                10,
            ),
            alertEmailEnabled:
                this.configService.get<string>(
                    'security.session.alertEmailEnabled',
                    'true',
                ) === 'true',
            autoRevokeEnabled:
                this.configService.get<string>(
                    'security.session.sessionAutoRevokeEnabled',
                    'true',
                ) === 'true',
            geoTrackingEnabled:
                this.configService.get<string>(
                    'security.session.sessionGeoTrackingEnabled',
                    'true',
                ) === 'true',
        };

        this.logger.log(
            'Configuration de sécurité chargée:',
            this.securityConfig,
        );
    }

    async analyzeLogin(
        user: User,
        ipAddress: string,
        userAgent: string,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        try {
            const sessionMetrics = await this.calculateSessionMetrics(
                user.id,
                ipAddress,
                userAgent,
            );

            const metricsAlerts =
                await this.analyzeSessionMetrics(sessionMetrics);
            alerts.push(...metricsAlerts);

            if (this.securityConfig.geoTrackingEnabled) {
                const locationAlerts = await this.analyzeLocation(
                    user.id,
                    ipAddress,
                    sessionMetrics,
                );
                alerts.push(...locationAlerts);
            }

            const sessionAlerts = await this.analyzeMultipleSessions(
                user.id,
                sessionMetrics,
            );
            alerts.push(...sessionAlerts);

            const deviceAlerts = await this.analyzeDevice(
                user.id,
                userAgent,
                sessionMetrics,
            );
            alerts.push(...deviceAlerts);

            const temporalAlerts = await this.analyzeTimingPatterns(
                user.id,
                sessionMetrics,
            );
            alerts.push(...temporalAlerts);

            if (this.securityConfig.alertEmailEnabled && alerts.length > 0) {
                await this.processAlerts(alerts);
            }

            return alerts;
        } catch (error) {
            this.logger.error(
                `Erreur lors de l'analyse d'anomalies: ${error.message}`,
            );
            return [];
        }
    }

    private async calculateSessionMetrics(
        userId: string,
        currentIp: string,
        currentUserAgent: string,
    ): Promise<SessionMetrics> {
        try {
            const activeSessions = await this.prisma.refreshToken.findMany({
                where: {
                    userId,
                    expiresAt: { gt: new Date() },
                    isRevoked: false,
                },
                select: {
                    id: true,
                    ipAddress: true,
                    userAgent: true,
                    createdAt: true,
                },
                orderBy: { createdAt: 'desc' },
            });

            const recentSessions = await this.prisma.refreshToken.findMany({
                where: {
                    userId,
                    createdAt: {
                        gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                    },
                },
                select: {
                    ipAddress: true,
                    userAgent: true,
                    createdAt: true,
                },
                orderBy: { createdAt: 'desc' },
                take: 100,
            });

            const uniqueCountries = new Set<string>();
            const uniqueDevices = new Set<string>();

            activeSessions.forEach((session) => {
                if (
                    session.ipAddress &&
                    this.securityConfig.geoTrackingEnabled
                ) {
                    const geo = geoip.lookup(session.ipAddress);
                    if (geo?.country) {
                        uniqueCountries.add(geo.country);
                    }
                }

                if (session.userAgent) {
                    const deviceType = this.extractDeviceType(
                        session.userAgent,
                    );
                    if (deviceType) {
                        uniqueDevices.add(deviceType);
                    }
                }
            });

            // ✅ CORRECTION: Définir currentGeo avant utilisation
            let currentGeo: geoip.Lookup | null = null;
            if (this.securityConfig.geoTrackingEnabled) {
                currentGeo = geoip.lookup(currentIp);
                if (currentGeo?.country) {
                    uniqueCountries.add(currentGeo.country);
                }
            }

            const currentDeviceType = this.extractDeviceType(currentUserAgent);
            if (currentDeviceType) {
                uniqueDevices.add(currentDeviceType);
            }

            const knownCountries = new Set<string>();
            recentSessions.forEach((session) => {
                if (session.ipAddress) {
                    const geo = geoip.lookup(session.ipAddress);
                    if (geo?.country) {
                        knownCountries.add(geo.country);
                    }
                }
            });

            // ✅ CORRECTION: Assurer que isNewLocation est toujours boolean
            const isNewLocation = Boolean(
                this.securityConfig.geoTrackingEnabled &&
                    currentGeo &&
                    knownCountries.size > 0 &&
                    !knownCountries.has(currentGeo.country),
            );

            const knownDevices = new Set<string>();
            recentSessions.forEach((session) => {
                if (session.userAgent) {
                    const deviceType = this.extractDeviceType(
                        session.userAgent,
                    );
                    if (deviceType) {
                        knownDevices.add(deviceType);
                    }
                }
            });

            // ✅ CORRECTION: Assurer que isNewDevice est toujours boolean
            const isNewDevice = Boolean(
                knownDevices.size > 0 && !knownDevices.has(currentDeviceType),
            );

            let suspiciousScore = 0;
            if (
                activeSessions.length >
                this.securityConfig.maxConcurrentSessions
            ) {
                suspiciousScore += 30;
            }
            if (uniqueCountries.size > 2) {
                suspiciousScore += 40;
            }
            if (isNewLocation) {
                suspiciousScore += 25;
            }
            if (isNewDevice) {
                suspiciousScore += 15;
            }
            if (uniqueDevices.size > 3) {
                suspiciousScore += 20;
            }

            // ✅ CORRECTION: Typage explicite pour sessionDurations
            const sessionDurations: number[] = [];
            for (const session of recentSessions.slice(0, 10)) {
                const estimatedDuration = 7 * 24 * 60 * 60 * 1000; // 7 jours en ms
                sessionDurations.push(estimatedDuration);
            }

            const averageSessionDuration =
                sessionDurations.length > 0
                    ? sessionDurations.reduce((a, b) => a + b, 0) /
                      sessionDurations.length
                    : 0;

            const recentLoginAttempts = await this.prisma.user.findUnique({
                where: { id: userId },
                select: { failedLoginAttempts: true },
            });

            return {
                userId,
                activeSessionCount: activeSessions.length,
                countriesCount: uniqueCountries.size,
                deviceTypesCount: uniqueDevices.size,
                suspiciousScore,
                lastLoginFromNewLocation: isNewLocation,
                lastLoginFromNewDevice: isNewDevice,
                recentLoginAttempts:
                    recentLoginAttempts?.failedLoginAttempts || 0,
                averageSessionDuration,
            };
        } catch (error) {
            this.logger.error(`Erreur calcul métriques: ${error.message}`);
            return {
                userId,
                activeSessionCount: 0,
                countriesCount: 0,
                deviceTypesCount: 0,
                suspiciousScore: 0,
                lastLoginFromNewLocation: false,
                lastLoginFromNewDevice: false,
                recentLoginAttempts: 0,
                averageSessionDuration: 0,
            };
        }
    }

    private async analyzeSessionMetrics(
        metrics: SessionMetrics,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        if (metrics.suspiciousScore >= 50) {
            alerts.push({
                userId: metrics.userId,
                type: 'SUSPICIOUS_LOGIN',
                severity: metrics.suspiciousScore >= 75 ? 'CRITICAL' : 'HIGH',
                details: {
                    suspiciousScore: metrics.suspiciousScore,
                    activeSessionCount: metrics.activeSessionCount,
                    countriesCount: metrics.countriesCount,
                    deviceTypesCount: metrics.deviceTypesCount,
                    newLocation: metrics.lastLoginFromNewLocation,
                    newDevice: metrics.lastLoginFromNewDevice,
                },
                timestamp: new Date(),
            });
        }

        if (
            metrics.activeSessionCount >
            this.securityConfig.maxConcurrentSessions * 2
        ) {
            alerts.push({
                userId: metrics.userId,
                type: 'MULTIPLE_SESSIONS',
                severity: 'CRITICAL',
                details: {
                    activeSessionCount: metrics.activeSessionCount,
                    maxAllowed: this.securityConfig.maxConcurrentSessions,
                    exceedsBy:
                        metrics.activeSessionCount -
                        this.securityConfig.maxConcurrentSessions,
                },
                timestamp: new Date(),
            });
        }

        return alerts;
    }

    private async analyzeLocation(
        userId: string,
        ipAddress: string,
        metrics: SessionMetrics,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        try {
            const geo = geoip.lookup(ipAddress);
            if (!geo) return alerts;

            if (metrics.lastLoginFromNewLocation) {
                alerts.push({
                    userId,
                    type: 'LOCATION_CHANGE',
                    severity: metrics.countriesCount > 2 ? 'HIGH' : 'MEDIUM',
                    details: {
                        newCountry: geo.country,
                        newCity: geo.city,
                        totalCountries: metrics.countriesCount,
                        ipAddress,
                        coordinates: `${geo.ll[0]}, ${geo.ll[1]}`,
                        timezone: geo.timezone,
                    },
                    timestamp: new Date(),
                });
            }

            if (metrics.countriesCount > 3) {
                alerts.push({
                    userId,
                    type: 'MULTIPLE_SESSIONS',
                    severity: 'CRITICAL',
                    details: {
                        countriesCount: metrics.countriesCount,
                        currentCountry: geo.country,
                        suspiciousScore: metrics.suspiciousScore,
                    },
                    timestamp: new Date(),
                });
            }
        } catch (error) {
            this.logger.error(`Erreur analyse géographique: ${error.message}`);
        }

        return alerts;
    }

    private async analyzeMultipleSessions(
        userId: string,
        metrics: SessionMetrics,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        try {
            if (
                metrics.activeSessionCount >=
                this.securityConfig.maxConcurrentSessions
            ) {
                const severity =
                    metrics.activeSessionCount >
                    this.securityConfig.maxConcurrentSessions * 1.5
                        ? 'HIGH'
                        : 'MEDIUM';

                alerts.push({
                    userId,
                    type: 'MULTIPLE_SESSIONS',
                    severity,
                    details: {
                        activeSessionsCount: metrics.activeSessionCount,
                        maxAllowed: this.securityConfig.maxConcurrentSessions,
                        countriesCount: metrics.countriesCount,
                        deviceTypesCount: metrics.deviceTypesCount,
                        suspiciousScore: metrics.suspiciousScore,
                    },
                    timestamp: new Date(),
                });
            }
        } catch (error) {
            this.logger.error(
                `Erreur analyse sessions multiples: ${error.message}`,
            );
        }

        return alerts;
    }

    private async analyzeDevice(
        userId: string,
        userAgent: string,
        metrics: SessionMetrics,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        try {
            const deviceInfo = this.parseUserAgent(userAgent);

            if (metrics.lastLoginFromNewDevice) {
                alerts.push({
                    userId,
                    type: 'UNUSUAL_ACTIVITY',
                    severity: 'MEDIUM',
                    details: {
                        newDevice: true,
                        deviceInfo,
                        totalDeviceTypes: metrics.deviceTypesCount,
                        userAgent,
                    },
                    timestamp: new Date(),
                });
            }

            if (metrics.deviceTypesCount > 4) {
                alerts.push({
                    userId,
                    type: 'UNUSUAL_ACTIVITY',
                    severity: 'HIGH',
                    details: {
                        deviceTypesCount: metrics.deviceTypesCount,
                        currentDevice: deviceInfo,
                        suspiciousScore: metrics.suspiciousScore,
                    },
                    timestamp: new Date(),
                });
            }
        } catch (error) {
            this.logger.error(`Erreur analyse appareils: ${error.message}`);
        }

        return alerts;
    }

    private async analyzeTimingPatterns(
        userId: string,
        metrics: SessionMetrics,
    ): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        try {
            const recentLogins = await this.prisma.refreshToken.findMany({
                where: {
                    userId,
                    createdAt: {
                        gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
                    },
                },
                select: {
                    createdAt: true,
                },
                orderBy: { createdAt: 'desc' },
                take: 10,
            });

            if (recentLogins.length > 6) {
                // ✅ CORRECTION: Typage explicite pour intervals
                const intervals: number[] = [];
                for (let i = 1; i < recentLogins.length; i++) {
                    const interval =
                        recentLogins[i - 1].createdAt.getTime() -
                        recentLogins[i].createdAt.getTime();
                    intervals.push(interval);
                }

                const averageInterval =
                    intervals.reduce((a, b) => a + b, 0) / intervals.length;
                const rapidConnections = intervals.filter(
                    (interval) => interval < 5 * 60 * 1000,
                );

                if (
                    rapidConnections.length > 3 ||
                    averageInterval < 30 * 60 * 1000
                ) {
                    alerts.push({
                        userId,
                        type: 'UNUSUAL_ACTIVITY',
                        severity: 'MEDIUM',
                        details: {
                            rapidConnectionsCount: rapidConnections.length,
                            averageIntervalMinutes: Math.round(
                                averageInterval / (60 * 1000),
                            ),
                            totalConnectionsLast24h: recentLogins.length,
                            suspiciousScore: metrics.suspiciousScore,
                        },
                        timestamp: new Date(),
                    });
                }
            }
        } catch (error) {
            this.logger.error(`Erreur analyse temporelle: ${error.message}`);
        }

        return alerts;
    }

    private async processAlerts(alerts: SecurityAlert[]): Promise<void> {
        for (const alert of alerts) {
            try {
                await this.storeAlert(alert);

                if (
                    this.securityConfig.alertEmailEnabled &&
                    (alert.severity === 'HIGH' || alert.severity === 'CRITICAL')
                ) {
                    await this.sendSecurityAlert(alert);
                }

                if (this.securityConfig.autoRevokeEnabled) {
                    await this.executeAutomaticActions(alert);
                }
            } catch (error) {
                this.logger.error(`Erreur traitement alerte: ${error.message}`);
            }
        }
    }

    private async storeAlert(alert: SecurityAlert): Promise<void> {
        this.logger.warn(`SECURITY_ALERT`, {
            type: alert.type,
            severity: alert.severity,
            userId: alert.userId,
            timestamp: alert.timestamp.toISOString(),
            details: alert.details,
        });
    }

    private async sendSecurityAlert(alert: SecurityAlert): Promise<void> {
        try {
            const user = await this.prisma.user.findUnique({
                where: { id: alert.userId },
                select: { email: true, firstName: true },
            });

            if (!user) return;

            const subject = `🚨 Alerte de sécurité - ${this.getAlertTypeLabel(alert.type)}`;
            let message = `Bonjour ${user.firstName || ''},\n\n`;

            switch (alert.type) {
                case 'LOCATION_CHANGE':
                    message += `Une connexion depuis un nouveau pays a été détectée :\n`;
                    message += `- Pays : ${alert.details.newCountry}\n`;
                    message += `- Ville : ${alert.details.newCity}\n`;
                    message += `- IP : ${alert.details.ipAddress}\n`;
                    if (alert.details.timezone) {
                        message += `- Fuseau horaire : ${alert.details.timezone}\n`;
                    }
                    break;

                case 'MULTIPLE_SESSIONS':
                    message += `Plusieurs sessions actives détectées :\n`;
                    message += `- Nombre de sessions : ${alert.details.activeSessionsCount || alert.details.simultaneousSessionsCount}\n`;
                    if (alert.details.countriesCount) {
                        message += `- Pays différents : ${alert.details.countriesCount}\n`;
                    }
                    break;

                case 'SUSPICIOUS_LOGIN':
                    message += `Activité de connexion suspecte détectée :\n`;
                    message += `- Score de risque : ${alert.details.suspiciousScore}/100\n`;
                    message += `- Sessions actives : ${alert.details.activeSessionCount}\n`;
                    if (alert.details.newLocation) {
                        message += `- Nouvelle localisation détectée\n`;
                    }
                    if (alert.details.newDevice) {
                        message += `- Nouvel appareil détecté\n`;
                    }
                    break;

                case 'UNUSUAL_ACTIVITY':
                    message += `Activité inhabituelle détectée :\n`;
                    if (alert.details.newDevice) {
                        message += `- Connexion depuis un nouvel appareil\n`;
                    }
                    if (alert.details.rapidConnectionsCount) {
                        message += `- Connexions fréquentes : ${alert.details.rapidConnectionsCount}\n`;
                    }
                    break;
            }

            message += `\nSi ce n'est pas vous, veuillez :\n`;
            message += `1. Changer votre mot de passe immédiatement\n`;
            message += `2. Déconnecter toutes les sessions\n`;
            message += `3. Contacter le support si nécessaire\n\n`;
            message += `Date : ${alert.timestamp.toLocaleString('fr-FR')}\n`;
            message += `Niveau d'alerte : ${alert.severity}`;

            await this.mailService.sendMail({
                to: user.email,
                subject,
                text: message,
            });

            this.logger.log(
                `Alerte sécurité envoyée à ${user.email} pour ${alert.type}`,
            );
        } catch (error) {
            this.logger.error(`Erreur envoi alerte: ${error.message}`);
        }
    }

    private async executeAutomaticActions(alert: SecurityAlert): Promise<void> {
        try {
            switch (alert.severity) {
                case 'CRITICAL':
                    await this.revokeOldSessions(alert.userId, 1);
                    this.logger.warn(
                        `Sessions révoquées automatiquement pour userId: ${alert.userId} (CRITICAL)`,
                    );
                    break;

                case 'HIGH':
                    if (
                        alert.type === 'LOCATION_CHANGE' &&
                        alert.details.countriesCount > 2
                    ) {
                        await this.revokeOldSessions(alert.userId, 2);
                        this.logger.warn(
                            `Sessions multiples révoquées pour userId: ${alert.userId} (HIGH)`,
                        );
                    }
                    break;

                case 'MEDIUM':
                    this.logger.warn(
                        `Action manuelle recommandée pour userId: ${alert.userId}`,
                        {
                            type: alert.type,
                            details: alert.details,
                        },
                    );
                    break;
            }
        } catch (error) {
            this.logger.error(`Erreur actions automatiques: ${error.message}`);
        }
    }

    private extractDeviceType(userAgent: string): string {
        if (!userAgent) return 'Unknown';

        const ua = userAgent.toLowerCase();

        if (ua.includes('mobile') || ua.includes('android')) return 'Mobile';
        if (ua.includes('tablet') || ua.includes('ipad')) return 'Tablet';
        if (ua.includes('windows')) return 'Windows';
        if (ua.includes('macintosh') || ua.includes('mac os')) return 'Mac';
        if (ua.includes('linux')) return 'Linux';
        if (ua.includes('chrome')) return 'Chrome Browser';
        if (ua.includes('firefox')) return 'Firefox Browser';
        if (ua.includes('safari')) return 'Safari Browser';

        return 'Unknown';
    }

    private parseUserAgent(userAgent: string) {
        const browserMatch = userAgent.match(
            /(Chrome|Firefox|Safari|Edge)\/[\d\.]+/,
        );
        const osMatch = userAgent.match(/(Windows|Mac OS|Linux|Android|iOS)/);

        return {
            browser: browserMatch ? browserMatch[1] : 'Unknown',
            os: osMatch ? osMatch[1] : 'Unknown',
            deviceType: this.extractDeviceType(userAgent),
            full: userAgent,
        };
    }

    private getAlertTypeLabel(type: string): string {
        const labels = {
            SUSPICIOUS_LOGIN: 'Connexion Suspecte',
            MULTIPLE_SESSIONS: 'Sessions Multiples',
            LOCATION_CHANGE: 'Changement de Localisation',
            UNUSUAL_ACTIVITY: 'Activité Inhabituelle',
            BRUTE_FORCE: 'Tentative de Force Brute',
        };
        return labels[type] || type;
    }

    private async revokeOldSessions(
        userId: string,
        keepCount: number = 1,
    ): Promise<void> {
        const sessions = await this.prisma.refreshToken.findMany({
            where: {
                userId,
                expiresAt: { gt: new Date() },
                isRevoked: false,
            },
            orderBy: { createdAt: 'desc' },
        });

        const sessionsToRevoke = sessions.slice(keepCount);

        if (sessionsToRevoke.length > 0) {
            await this.prisma.refreshToken.updateMany({
                where: {
                    id: { in: sessionsToRevoke.map((s) => s.id) },
                },
                data: { isRevoked: true },
            });

            this.logger.log(
                `${sessionsToRevoke.length} sessions révoquées pour userId: ${userId}`,
            );
        }
    }

    // ✅ MÉTHODES PUBLIQUES AVEC TYPES DE RETOUR EXPLICITES
    async getUserSecurityMetrics(userId: string): Promise<SessionMetrics> {
        return await this.calculateSessionMetrics(userId, '', '');
    }

    async getSecurityDashboard(): Promise<{
        totalActiveSessions: number;
        usersWithMultipleSessions: number;
        newSessionsLast24h: number;
        configuration: SecurityConfig;
    } | null> {
        try {
            const now = new Date();
            const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            const stats = {
                totalActiveSessions: await this.prisma.refreshToken.count({
                    where: {
                        expiresAt: { gt: now },
                        isRevoked: false,
                    },
                }),

                usersWithMultipleSessions: await this.prisma.refreshToken
                    .groupBy({
                        by: ['userId'],
                        where: {
                            expiresAt: { gt: now },
                            isRevoked: false,
                        },
                        _count: { userId: true },
                        having: {
                            userId: {
                                _count: {
                                    gt: this.securityConfig
                                        .maxConcurrentSessions,
                                },
                            },
                        },
                    })
                    .then((result) => result.length),

                newSessionsLast24h: await this.prisma.refreshToken.count({
                    where: {
                        createdAt: { gte: last24h },
                        isRevoked: false,
                    },
                }),

                configuration: this.securityConfig,
            };

            return stats;
        } catch (error) {
            this.logger.error(`Erreur dashboard sécurité: ${error.message}`);
            return null;
        }
    }

    @Cron(CronExpression.EVERY_HOUR)
    async performMaintenanceTasks() {
        this.logger.debug('Exécution des tâches de maintenance sécurité');

        try {
            const deletedCount = await this.prisma.refreshToken.deleteMany({
                where: {
                    OR: [
                        { expiresAt: { lt: new Date() } },
                        { isRevoked: true },
                    ],
                },
            });

            if (deletedCount.count > 0) {
                this.logger.log(
                    `${deletedCount.count} sessions expirées supprimées`,
                );
            }
        } catch (error) {
            this.logger.error(`Erreur nettoyage sessions: ${error.message}`);
        }
    }

    @Cron(CronExpression.EVERY_DAY_AT_2AM)
    async generateDailySecurityReport() {
        try {
            const dashboard = await this.getSecurityDashboard();

            if (dashboard) {
                this.logger.log('Rapport de sécurité quotidien', {
                    totalActiveSessions: dashboard.totalActiveSessions,
                    usersWithMultipleSessions:
                        dashboard.usersWithMultipleSessions,
                    newSessionsLast24h: dashboard.newSessionsLast24h,
                    configuration: dashboard.configuration,
                });

                if (dashboard.usersWithMultipleSessions > 5) {
                    this.logger.warn(
                        `Attention: ${dashboard.usersWithMultipleSessions} utilisateurs avec sessions multiples`,
                    );
                }
            }
        } catch (error) {
            this.logger.error(
                `Erreur génération rapport quotidien: ${error.message}`,
            );
        }
    }
}
