export interface ITwoFactorService {
    generateSecret(
        email: string,
    ): Promise<{ secret: string; qrCodeUrl: string }>;
    verifyCode(code: string, secret: string): boolean;
    enable(userId: string, secret: string): Promise<string[]>;
    disable(userId: string): Promise<void>;
    validateRecoveryCode(userId: string, code: string): Promise<boolean>;
    regenerateRecoveryCodes(userId: string): Promise<string[]>;
}
