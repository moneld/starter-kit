import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { addMonths } from 'date-fns';
import { PrismaService } from '../../modules/prisma/prisma.service';

@Injectable()
export class CryptoService implements OnModuleInit {
    private readonly logger = new Logger(CryptoService.name);
    private readonly masterKey: Buffer;
    private readonly algorithm = 'aes-256-gcm';
    private readonly ivLength = 16;
    private readonly authTagLength = 16;
    private currentKeyVersion: number = 0;
    private encryptionKeys: Map<number, Buffer> = new Map();
    private keyRotationInterval: number; // en jours

    constructor(
        private readonly configService: ConfigService,
        private readonly prisma: PrismaService,
    ) {
        // La clé maître (racine) qui sera utilisée pour chiffrer/déchiffrer les clés de données
        const masterKeyString = this.configService.get<string>(
            'security.encryption.masterKey',
        );

        if (!masterKeyString) {
            this.logger.error(
                "MASTER_ENCRYPTION_KEY non définie dans les variables d'environnement",
            );
            throw new Error('MASTER_ENCRYPTION_KEY manquante');
        }

        // Dériver la clé maître
        this.masterKey = crypto
            .createHash('sha256')
            .update(masterKeyString)
            .digest();

        // Configurer l'intervalle de rotation (par défaut 90 jours)
        this.keyRotationInterval = this.configService.get<number>(
            'security.encryption.keyRotationInterval',
            90,
        );
    }

    async onModuleInit() {
        await this.loadEncryptionKeys();
    }

    /**
     * Charge toutes les clés de chiffrement depuis la base de données
     */
    private async loadEncryptionKeys(): Promise<void> {
        try {
            const keys = await this.prisma.encryptionKey.findMany({
                orderBy: { version: 'desc' },
            });

            if (keys.length === 0) {
                // Pas de clés existantes, créer la première
                await this.createNewEncryptionKey();
            } else {
                // Charger les clés existantes
                for (const key of keys) {
                    // Déchiffrer la clé avec la clé maître
                    const decryptedKey = this.decryptWithMasterKey(key.key);
                    this.encryptionKeys.set(
                        key.version,
                        Buffer.from(decryptedKey, 'hex'),
                    );

                    // Identifier la clé active courante
                    if (key.isActive) {
                        this.currentKeyVersion = key.version;
                    }
                }

                // Vérifier si la rotation de la clé est nécessaire
                const activeKey = keys.find((k) => k.isActive);
                if (
                    activeKey &&
                    activeKey.expiresAt &&
                    new Date() > activeKey.expiresAt
                ) {
                    this.logger.log(
                        "La clé active a expiré, création d'une nouvelle clé...",
                    );
                    await this.rotateEncryptionKey();
                }
            }

            this.logger.log(
                `Clés de chiffrement chargées, version actuelle: ${this.currentKeyVersion}`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors du chargement des clés: ${error.message}`,
            );
            throw new Error('Impossible de charger les clés de chiffrement');
        }
    }

    /**
     * Crée une nouvelle clé de chiffrement et la définit comme active
     */
    private async createNewEncryptionKey(): Promise<void> {
        try {
            // Générer une nouvelle clé aléatoire
            const newKey = crypto.randomBytes(32);

            // Déterminer la prochaine version
            const latestKey = await this.prisma.encryptionKey.findFirst({
                orderBy: { version: 'desc' },
            });

            const newVersion = latestKey ? latestKey.version + 1 : 1;

            // Chiffrer la clé avec la clé maître
            const encryptedKey = this.encryptWithMasterKey(
                newKey.toString('hex'),
            );

            // Définir la date d'expiration
            const expiresAt = addMonths(
                new Date(),
                this.keyRotationInterval / 30,
            ); // approximation

            // Désactiver toutes les clés existantes
            if (latestKey) {
                await this.prisma.encryptionKey.updateMany({
                    where: { isActive: true },
                    data: { isActive: false },
                });
            }

            // Enregistrer la nouvelle clé
            await this.prisma.encryptionKey.create({
                data: {
                    version: newVersion,
                    key: encryptedKey,
                    isActive: true,
                    expiresAt,
                },
            });

            // Mettre à jour le cache local
            this.encryptionKeys.set(newVersion, newKey);
            this.currentKeyVersion = newVersion;

            this.logger.log(
                `Nouvelle clé de chiffrement créée (version ${newVersion})`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors de la création d'une nouvelle clé: ${error.message}`,
            );
            throw new Error(
                'Impossible de créer une nouvelle clé de chiffrement',
            );
        }
    }

    /**
     * Effectue la rotation des clés de chiffrement
     */
    public async rotateEncryptionKey(): Promise<void> {
        this.logger.log('Début de la rotation des clés de chiffrement...');

        try {
            // Créer une nouvelle clé
            await this.createNewEncryptionKey();

            // Optionnel: Re-chiffrer les données existantes avec la nouvelle clé
            // Cette étape est complexe et nécessite un traitement par lots
            await this.reencryptSensitiveData();

            this.logger.log('Rotation des clés terminée avec succès');
        } catch (error) {
            this.logger.error(
                `Erreur lors de la rotation des clés: ${error.message}`,
            );
            throw new Error('Échec de la rotation des clés');
        }
    }

    /**
     * Rechiffre toutes les données sensibles avec la nouvelle clé
     * Note: Cette méthode doit être implémentée selon la structure spécifique de vos données
     */
    private async reencryptSensitiveData(): Promise<void> {
        try {
            // Exemple: Re-chiffrer les secrets 2FA
            const users = await this.prisma.user.findMany({
                where: {
                    isTwoFactorEnabled: true,
                    twoFactorSecret: { not: null },
                },
                select: {
                    id: true,
                    twoFactorSecret: true,
                    twoFactorRecoveryCodes: true,
                },
            });

            this.logger.log(
                `Re-chiffrement des données pour ${users.length} utilisateurs...`,
            );

            // Traiter par lots pour éviter de surcharger la base de données
            const batchSize = 100;
            for (let i = 0; i < users.length; i += batchSize) {
                const batch = users.slice(i, i + batchSize);

                await Promise.all(
                    batch.map(async (user) => {
                        try {
                            // Vérifier si les données existent avant de les déchiffrer
                            if (user.twoFactorSecret) {
                                // Déchiffrer avec l'ancienne clé
                                const decryptedSecret = this.decrypt(
                                    user.twoFactorSecret,
                                );
                                // Re-chiffrer avec la nouvelle clé
                                const newEncryptedSecret =
                                    this.encrypt(decryptedSecret);

                                // Préparer les données à mettre à jour
                                const updateData: {
                                    twoFactorSecret: string;
                                    twoFactorRecoveryCodes?: string | null;
                                } = {
                                    twoFactorSecret: newEncryptedSecret,
                                };

                                // Faire de même pour les codes de récupération s'ils existent
                                if (user.twoFactorRecoveryCodes) {
                                    const decryptedCodes = this.decrypt(
                                        user.twoFactorRecoveryCodes,
                                    );
                                    updateData.twoFactorRecoveryCodes =
                                        this.encrypt(decryptedCodes);
                                }

                                // Mettre à jour en base de données
                                await this.prisma.user.update({
                                    where: { id: user.id },
                                    data: updateData,
                                });
                            }
                        } catch (error) {
                            this.logger.error(
                                `Erreur lors du re-chiffrement pour l'utilisateur ${user.id}: ${error.message}`,
                            );
                        }
                    }),
                );

                this.logger.log(
                    `Traité ${Math.min(i + batchSize, users.length)}/${users.length} utilisateurs`,
                );
            }

            // Répéter pour d'autres données sensibles...
        } catch (error) {
            this.logger.error(
                `Erreur lors du re-chiffrement des données: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Chiffre une chaîne avec la clé maître (pour chiffrer les clés de chiffrement)
     */
    private encryptWithMasterKey(text: string): string {
        const iv = crypto.randomBytes(this.ivLength);
        const cipher = crypto.createCipheriv(
            this.algorithm,
            this.masterKey,
            iv,
        );

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return Buffer.concat([
            iv,
            authTag,
            Buffer.from(encrypted, 'hex'),
        ]).toString('hex');
    }

    /**
     * Déchiffre une chaîne avec la clé maître
     */
    private decryptWithMasterKey(encryptedHex: string): string {
        const encryptedBuffer = Buffer.from(encryptedHex, 'hex');

        const iv = encryptedBuffer.subarray(0, this.ivLength);
        const authTag = encryptedBuffer.subarray(
            this.ivLength,
            this.ivLength + this.authTagLength,
        );
        const encryptedText = encryptedBuffer
            .subarray(this.ivLength + this.authTagLength)
            .toString('hex');

        const decipher = crypto.createDecipheriv(
            this.algorithm,
            this.masterKey,
            iv,
        );
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    /**
     * Chiffre une chaîne avec la clé active courante
     * Stocke la version de clé utilisée avec les données chiffrées
     */
    encrypt(text: string): string {
        try {
            const currentKey = this.encryptionKeys.get(this.currentKeyVersion);
            if (!currentKey) {
                throw new Error('Aucune clé de chiffrement active disponible');
            }

            // Générer IV et chiffrer
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipheriv(
                this.algorithm,
                currentKey,
                iv,
            );

            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Obtenir le tag d'authentification
            const authTag = cipher.getAuthTag();

            // Construire le résultat: version de clé + IV + tag d'auth + texte chiffré
            const versionByte = Buffer.alloc(1);
            versionByte.writeUInt8(this.currentKeyVersion);

            return Buffer.concat([
                versionByte,
                iv,
                authTag,
                Buffer.from(encrypted, 'hex'),
            ]).toString('hex');
        } catch (error) {
            this.logger.error(`Erreur de chiffrement: ${error.message}`);
            throw new Error('Erreur lors du chiffrement des données');
        }
    }

    /**
     * Déchiffre une chaîne en utilisant la version de clé stockée avec les données
     */
    decrypt(encryptedHex: string): string {
        try {
            const encryptedBuffer = Buffer.from(encryptedHex, 'hex');

            // Extraire la version de la clé (premier octet)
            const keyVersion = encryptedBuffer.readUInt8(0);

            // Trouver la clé correspondante
            const key = this.encryptionKeys.get(keyVersion);
            if (!key) {
                throw new Error(
                    `Clé de chiffrement version ${keyVersion} non trouvée`,
                );
            }

            // Extraire IV, AuthTag et texte chiffré
            const iv = encryptedBuffer.subarray(1, 1 + this.ivLength);
            const authTag = encryptedBuffer.subarray(
                1 + this.ivLength,
                1 + this.ivLength + this.authTagLength,
            );
            const encryptedText = encryptedBuffer
                .subarray(1 + this.ivLength + this.authTagLength)
                .toString('hex');

            // Déchiffrer
            const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);

            let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            this.logger.error(`Erreur de déchiffrement: ${error.message}`);
            throw new Error('Erreur lors du déchiffrement des données');
        }
    }

    /**
     * Génère une chaîne aléatoire sécurisée
     */
    generateSecureToken(length = 32): string {
        return crypto.randomBytes(length).toString('hex');
    }
}
