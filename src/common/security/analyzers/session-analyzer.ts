import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../modules/prisma/prisma.service';
import {
    SecurityAlert,
    SecurityContext,
} from '../../interfaces/security-analyzer.interface';
import { BaseSecurityAnalyzer } from './base-security.analyzer';

@Injectable()
export class SessionAnalyzer extends BaseSecurityAnalyzer {
    private readonly maxConcurrentSessions: number;

    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
    ) {
        super('SessionAnalyzer');
        this.maxConcurrentSessions = parseInt(
            this.configService.get<string>(
                'security.session.maxConcurrentSessions',
                '3',
            ),
            10,
        );
    }

    async analyze(context: SecurityContext): Promise<SecurityAlert[]> {
        const alerts: SecurityAlert[] = [];

        // Count active sessions
        const activeSessions = await this.prisma.refreshToken.count({
            where: {
                userId: context.user.id,
                expiresAt: { gt: new Date() },
                isRevoked: false,
            },
        });

        // Check for too many concurrent sessions
        if (activeSessions > this.maxConcurrentSessions) {
            const severity =
                activeSessions > this.maxConcurrentSessions * 2
                    ? 'CRITICAL'
                    : 'HIGH';

            alerts.push(
                this.createAlert(
                    'MULTIPLE_SESSIONS',
                    severity,
                    `Multiple concurrent sessions detected: ${activeSessions}`,
                    {
                        activeSessionCount: activeSessions,
                        maxAllowed: this.maxConcurrentSessions,
                        exceedsBy: activeSessions - this.maxConcurrentSessions,
                    },
                ),
            );
        }

        // Check for rapid session creation
        const recentSessions = await this.checkRapidSessionCreation(
            context.user.id,
        );
        if (recentSessions) {
            alerts.push(recentSessions);
        }

        return alerts;
    }

    getPriority(): number {
        return 20;
    }

    private async checkRapidSessionCreation(
        userId: string,
    ): Promise<SecurityAlert | null> {
        const oneHourAgo = new Date();
        oneHourAgo.setHours(oneHourAgo.getHours() - 1);

        const recentSessions = await this.prisma.refreshToken.count({
            where: {
                userId,
                createdAt: { gte: oneHourAgo },
            },
        });

        if (recentSessions > 5) {
            return this.createAlert(
                'RAPID_SESSION_CREATION',
                'HIGH',
                'Unusual number of sessions created in short time',
                {
                    sessionsInLastHour: recentSessions,
                    threshold: 5,
                },
            );
        }

        return null;
    }
}
