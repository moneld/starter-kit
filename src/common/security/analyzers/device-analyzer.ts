import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../modules/prisma/prisma.service';
import {
  SecurityAlert,
  SecurityContext,
} from '../../interfaces/security-analyzer.interface';
import { BaseSecurityAnalyzer } from './base-security.analyzer';

@Injectable()
export class DeviceAnalyzer extends BaseSecurityAnalyzer {
  constructor(private readonly prisma: PrismaService) {
    super('DeviceAnalyzer');
  }

  async analyze(context: SecurityContext): Promise<SecurityAlert[]> {
    const alerts: SecurityAlert[] = [];

    const deviceInfo = this.parseUserAgent(context.userAgent);
    const recentDevices = await this.getRecentDevices(context.user.id);

    // Check if this is a new device
    const deviceKey = `${deviceInfo.os}-${deviceInfo.browser}`;
    const isNewDevice = !recentDevices.has(deviceKey);

    if (isNewDevice && recentDevices.size > 0) {
      alerts.push(
        this.createAlert(
          'NEW_DEVICE',
          'MEDIUM',
          'Login from new device detected',
          {
            newDevice: deviceInfo,
            knownDevices: Array.from(recentDevices),
            userAgent: context.userAgent,
          },
        ),
      );
    }

    // Check for suspicious user agent
    if (this.isSuspiciousUserAgent(context.userAgent)) {
      alerts.push(
        this.createAlert(
          'SUSPICIOUS_USER_AGENT',
          'HIGH',
          'Suspicious user agent detected',
          {
            userAgent: context.userAgent,
            deviceInfo,
          },
        ),
      );
    }

    return alerts;
  }

  getPriority(): number {
    return 30;
  }

  private async getRecentDevices(userId: string): Promise<Set<string>> {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentTokens = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        createdAt: { gte: thirtyDaysAgo },
      },
      select: { userAgent: true },
      take: 100,
    });

    const devices = new Set<string>();

    for (const token of recentTokens) {
      if (token.userAgent) {
        const info = this.parseUserAgent(token.userAgent);
        devices.add(`${info.os}-${info.browser}`);
      }
    }

    return devices;
  }

  private parseUserAgent(userAgent: string): {
    browser: string;
    os: string;
    deviceType: string;
  } {
    const browserMatch = userAgent.match(
      /(Chrome|Firefox|Safari|Edge)\/[\d\.]+/,
    );
    const osMatch = userAgent.match(/(Windows|Mac OS|Linux|Android|iOS)/);

    return {
      browser: browserMatch ? browserMatch[1] : 'Unknown',
      os: osMatch ? osMatch[1] : 'Unknown',
      deviceType: this.getDeviceType(userAgent),
    };
  }

  private getDeviceType(userAgent: string): string {
    const ua = userAgent.toLowerCase();
    if (ua.includes('mobile') || ua.includes('android')) return 'Mobile';
    if (ua.includes('tablet') || ua.includes('ipad')) return 'Tablet';
    return 'Desktop';
  }

  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java(?!script)/i,
    ];

    return suspiciousPatterns.some((pattern) => pattern.test(userAgent));
  }
}
