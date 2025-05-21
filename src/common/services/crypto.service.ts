import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class CryptoService {
    private readonly logger = new Logger(CryptoService.name);
    private readonly encryptionKey: Buffer;
    private readonly algorithm = 'aes-256-gcm';
    private readonly ivLength = 16; // 16 bytes
    private readonly authTagLength = 16; // 16 bytes

    constructor(private readonly configService: ConfigService) {
        // Récupérer la clé de chiffrement depuis la configuration
        const keyString = this.configService.get<string>(
            'security.encryption.secretKey',
        );

        if (!keyString) {
            this.logger.error(
                "ENCRYPTION_KEY non définie dans les variables d'environnement",
            );
            throw new Error('ENCRYPTION_KEY manquante');
        }

        // Dériver une clé de 32 octets (256 bits) à partir de la clé fournie
        this.encryptionKey = crypto
            .createHash('sha256')
            .update(keyString)
            .digest();
    }

    /**
     * Chiffre une chaîne de caractères
     * @param text Texte à chiffrer
     * @returns Texte chiffré en format hexadécimal
     */
    encrypt(text: string): string {
        try {
            // Générer un vecteur d'initialisation aléatoire
            const iv = crypto.randomBytes(this.ivLength);

            // Créer le chiffreur avec l'algorithme, la clé et l'IV
            const cipher = crypto.createCipheriv(
                this.algorithm,
                this.encryptionKey,
                iv,
            );

            // Chiffrer les données
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Obtenir le tag d'authentification
            const authTag = cipher.getAuthTag();

            // Combiner IV + AuthTag + Texte chiffré
            return Buffer.concat([
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
     * Déchiffre une chaîne de caractères
     * @param encryptedHex Texte chiffré en format hexadécimal
     * @returns Texte déchiffré
     */
    decrypt(encryptedHex: string): string {
        try {
            // Convertir la chaîne hexadécimale en buffer
            const encryptedBuffer = Buffer.from(encryptedHex, 'hex');

            // Extraire IV, AuthTag et texte chiffré
            const iv = encryptedBuffer.subarray(0, this.ivLength);
            const authTag = encryptedBuffer.subarray(
                this.ivLength,
                this.ivLength + this.authTagLength,
            );
            const encryptedText = encryptedBuffer
                .subarray(this.ivLength + this.authTagLength)
                .toString('hex');

            // Créer le déchiffreur
            const decipher = crypto.createDecipheriv(
                this.algorithm,
                this.encryptionKey,
                iv,
            );

            // Définir le tag d'authentification
            decipher.setAuthTag(authTag);

            // Déchiffrer les données
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
     * @param length Longueur de la chaîne (par défaut 32 caractères)
     * @returns Chaîne aléatoire en format hexadécimal
     */
    generateSecureToken(length = 32): string {
        return crypto.randomBytes(length).toString('hex');
    }
}
