import {
    PasswordResetToken,
    RefreshToken,
    VerificationToken,
} from 'generated/prisma';

export interface IRefreshTokenRepository {
    create(data: {
        token: string;
        userId: string;
        expiresAt: Date;
        userAgent?: string;
        ipAddress?: string;
    }): Promise<RefreshToken>;
    findByToken(encryptedToken: string): Promise<RefreshToken | null>;
    findActiveByUserId(userId: string): Promise<RefreshToken[]>;
    revokeByToken(token: string): Promise<boolean>;
    revokeAllByUserId(userId: string): Promise<void>;
    deleteExpired(): Promise<number>;
}

export interface IVerificationTokenRepository {
    create(
        userId: string,
        token: string,
        expiresAt: Date,
    ): Promise<VerificationToken>;
    findByToken(token: string): Promise<VerificationToken | null>;
    delete(id: string): Promise<void>;
    deleteByUserId(userId: string): Promise<void>;
}

export interface IPasswordResetTokenRepository {
    create(
        userId: string,
        token: string,
        expiresAt: Date,
    ): Promise<PasswordResetToken>;
    findByToken(token: string): Promise<PasswordResetToken | null>;
    delete(id: string): Promise<void>;
    deleteByUserId(userId: string): Promise<void>;
}
