import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { CryptoService } from './crypto.service';
import { PrismaService } from '../../modules/prisma/prisma.service';

@Injectable()
export class KeyRotationService {
    private readonly logger = new Logger(KeyRotationService.name);

    constructor(
        private readonly cryptoService: CryptoService,
        private readonly prisma: PrismaService,
    ) {}

    /**
     * Vérifie chaque jour si la rotation des clés est nécessaire
     */
    @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
    async checkKeyRotation() {
        this.logger.log('Vérification de la rotation des clés...');

        try {
            // Vérifier s'il y a une clé active qui a expiré
            const expiredKey = await this.prisma.encryptionKey.findFirst({
                where: {
                    isActive: true,
                    expiresAt: {
                        lt: new Date(),
                    },
                },
            });

            if (expiredKey) {
                this.logger.log(`La clé active (version ${expiredKey.version}) a expiré, rotation en cours...`);
                await this.cryptoService.rotateEncryptionKey();
            } else {
                this.logger.log('Aucune rotation de clé nécessaire pour le moment');
            }
        } catch (error) {
            this.logger.error(`Erreur lors de la vérification de rotation des clés: ${error.message}`);
        }
    }

    /**
     * Force la rotation des clés (pour l'administration)
     */
    async forceKeyRotation(): Promise<void> {
        this.logger.log('Rotation forcée des clés demandée');
        await this.cryptoService.rotateEncryptionKey();
    }
}