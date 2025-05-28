import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as geoip from 'geoip-lite';
import { PrismaService } from '../../../modules/prisma/prisma.service';
import {
  SecurityAlert,
  SecurityContext,
} from '../../interfaces/security-analyzer.interface';
import { BaseSecurityAnalyzer } from './base-security.analyzer';

@Injectable()
export class LocationAnalyzer extends BaseSecurityAnalyzer {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {
    super('LocationAnalyzer');
  }

  async analyze(context: SecurityContext): Promise<SecurityAlert[]> {
    const alerts: SecurityAlert[] = [];

    if (!this.isGeoTrackingEnabled()) {
      return alerts;
    }

    const currentGeo = geoip.lookup(context.ipAddress);
    if (!currentGeo) {
      return alerts;
    }

    // Get user's recent login locations
    const recentLocations = await this.getRecentLocations(context.user.id);

    // Check if this is a new country
    const isNewCountry = !recentLocations.has(currentGeo.country);

    if (isNewCountry) {
      alerts.push(
        this.createAlert(
          'LOCATION_CHANGE',
          recentLocations.size === 0 ? 'MEDIUM' : 'HIGH',
          `Login from new country: ${currentGeo.country}`,
          {
            newCountry: currentGeo.country,
            newCity: currentGeo.city,
            ipAddress: context.ipAddress,
            coordinates: currentGeo.ll,
            timezone: currentGeo.timezone,
            knownCountries: Array.from(recentLocations),
          },
        ),
      );
    }

    // Check for impossible travel
    const impossibleTravel = await this.checkImpossibleTravel(
      context.user.id,
      currentGeo,
      context.timestamp,
    );

    if (impossibleTravel) {
      alerts.push(
        this.createAlert(
          'IMPOSSIBLE_TRAVEL',
          'CRITICAL',
          'Impossible travel detected',
          impossibleTravel,
        ),
      );
    }

    return alerts;
  }

  getPriority(): number {
    return 10;
  }

  private isGeoTrackingEnabled(): boolean {
    return (
      this.configService.get<string>(
        'security.session.sessionGeoTrackingEnabled',
        'true',
      ) === 'true'
    );
  }

  private async getRecentLocations(userId: string): Promise<Set<string>> {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentTokens = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        createdAt: { gte: thirtyDaysAgo },
      },
      select: { ipAddress: true },
      take: 100,
    });

    const countries = new Set<string>();

    for (const token of recentTokens) {
      if (token.ipAddress) {
        const geo = geoip.lookup(token.ipAddress);
        if (geo?.country) {
          countries.add(geo.country);
        }
      }
    }

    return countries;
  }

  private async checkImpossibleTravel(
    userId: string,
    currentGeo: geoip.Lookup,
    currentTime: Date,
  ): Promise<any | null> {
    // Get last login
    const lastLogin = await this.prisma.refreshToken.findFirst({
      where: {
        userId,
        createdAt: { lt: currentTime },
      },
      orderBy: { createdAt: 'desc' },
      select: { ipAddress: true, createdAt: true },
    });

    if (!lastLogin?.ipAddress) {
      return null;
    }

    const lastGeo = geoip.lookup(lastLogin.ipAddress);
    if (!lastGeo) {
      return null;
    }

    // Calculate distance and time
    const distance = this.calculateDistance(
      currentGeo.ll[0],
      currentGeo.ll[1],
      lastGeo.ll[0],
      lastGeo.ll[1],
    );

    const timeDiff =
      (currentTime.getTime() - lastLogin.createdAt.getTime()) /
      1000 /
      60 /
      60; // hours

    // Check if travel is impossible (assuming max speed of 1000 km/h for flights)
    const maxPossibleDistance = timeDiff * 1000;

    if (distance > maxPossibleDistance) {
      return {
        lastLocation: {
          country: lastGeo.country,
          city: lastGeo.city,
          timestamp: lastLogin.createdAt,
        },
        currentLocation: {
          country: currentGeo.country,
          city: currentGeo.city,
          timestamp: currentTime,
        },
        distance: Math.round(distance),
        timeDifferenceHours: Math.round(timeDiff * 10) / 10,
        impossibleTravel: true,
      };
    }

    return null;
  }

  private calculateDistance(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number,
  ): number {
    const R = 6371; // Earth's radius in km
    const dLat = this.toRad(lat2 - lat1);
    const dLon = this.toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRad(lat1)) *
      Math.cos(this.toRad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRad(value: number): number {
    return (value * Math.PI) / 180;
  }
}
