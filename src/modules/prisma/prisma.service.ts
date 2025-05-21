import {
    Injectable,
    Logger,
    OnModuleDestroy,
    OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from 'generated/prisma';

@Injectable()
export class PrismaService
    extends PrismaClient
    implements OnModuleInit, OnModuleDestroy
{
    private readonly logger = new Logger(PrismaService.name);

    constructor(private configService: ConfigService) {
        super({
            log:
                configService.get('app.general.nodeEnv') === 'development'
                    ? [
                          { level: 'query', emit: 'stdout' },
                          { level: 'error', emit: 'stdout' },
                      ]
                    : [{ level: 'error', emit: 'stdout' }],
        });
    }

    async onModuleInit() {
        await this.$connect();
        this.logger.log('Prisma connected successfully');
    }

    async onModuleDestroy() {
        await this.$disconnect();
        this.logger.log('Prisma disconnected successfully');
    }
}
