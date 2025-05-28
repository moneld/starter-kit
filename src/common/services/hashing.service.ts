import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { IHashingService } from '../interfaces/hashing.interface';

@Injectable()
export class HashingService implements IHashingService {
  private readonly logger = new Logger(HashingService.name);
  private readonly argon2Options: argon2.Options;

  constructor(private readonly configService: ConfigService) {
    this.argon2Options = {
      type: argon2.argon2id,
      memoryCost: this.configService.get<number>(
        'security.argon2.memoryCost',
        65536,
      ),
      timeCost: this.configService.get<number>(
        'security.argon2.timeCost',
        3,
      ),
      parallelism: this.configService.get<number>(
        'security.argon2.parallelismCost',
        4,
      ),
    };
  }

  async hash(plainText: string): Promise<string> {
    try {
      if (
        !plainText ||
        typeof plainText !== 'string' ||
        plainText.trim().length === 0
      ) {
        throw new Error('Invalid input for hashing');
      }

      return await argon2.hash(plainText, this.argon2Options);
    } catch (error) {
      this.logger.error(`Hashing error: ${error.message}`);
      throw new Error('Failed to hash password');
    }
  }

  async verify(plainText: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plainText);
    } catch (error) {
      this.logger.error(`Verification error: ${error.message}`);
      return false;
    }
  }
}
