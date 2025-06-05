import { Injectable } from '@nestjs/common';
import { IEncryptionService } from '../interfaces/encryption.interface';
import { CryptoService } from './crypto.service';

@Injectable()
export class EncryptionAdapter implements IEncryptionService {
    constructor(private readonly cryptoService: CryptoService) {}

    encrypt(plainText: string): string {
        return this.cryptoService.encrypt(plainText);
    }

    decrypt(encryptedText: string): string {
        return this.cryptoService.decrypt(encryptedText);
    }

    generateSecureToken(length?: number): string {
        return this.cryptoService.generateSecureToken(length);
    }
}
