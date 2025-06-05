export const INJECTION_TOKENS = {
    // Authentication tokens
    AUTHENTICATION_SERVICE: Symbol('IAuthenticationService'),
    PASSWORD_SERVICE: Symbol('IPasswordService'),
    JWT_TOKEN_SERVICE: Symbol('IJwtTokenService'),
    VERIFICATION_TOKEN_SERVICE: Symbol('IVerificationTokenService'),
    PASSWORD_RESET_TOKEN_SERVICE: Symbol('IPasswordResetTokenService'),
    TWO_FACTOR_SERVICE: Symbol('ITwoFactorService'),

    // Repository tokens
    USER_REPOSITORY: Symbol('IUserRepository'),
    REFRESH_TOKEN_REPOSITORY: Symbol('IRefreshTokenRepository'),
    VERIFICATION_TOKEN_REPOSITORY: Symbol('IVerificationTokenRepository'),
    PASSWORD_RESET_TOKEN_REPOSITORY: Symbol('IPasswordResetTokenRepository'),

    // Service tokens
    ENCRYPTION_SERVICE: Symbol('IEncryptionService'),
    HASHING_SERVICE: Symbol('IHashingService'),
    ACCOUNT_LOCK_SERVICE: Symbol('IAccountLockService'),
    EMAIL_SERVICE: Symbol('IEmailService'),
    EMAIL_PROVIDER: Symbol('IEmailProvider'),
};
