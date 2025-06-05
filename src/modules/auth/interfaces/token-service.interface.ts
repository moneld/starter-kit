export interface IJwtTokenService {
    generateAccessToken(payload: any): string;
    generateRefreshToken(payload: any): string;
    generateTwoFactorToken(payload: any): string;
    verifyToken(token: string, type: 'access' | 'refresh'): any;
    refreshTokens(
        refreshToken: string,
    ): Promise<{ accessToken: string; refreshToken: string }>;
}

export interface IVerificationTokenService {
    createEmailVerificationToken(userId: string): Promise<string>;
    verifyEmailToken(token: string): Promise<string | null>;
}

export interface IPasswordResetTokenService {
    createPasswordResetToken(userId: string): Promise<string>;
    verifyPasswordResetToken(token: string): Promise<string | null>;
}
