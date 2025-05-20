import { registerAs } from '@nestjs/config';

export const securityConfig = registerAs('security', () => ({
  // JWT
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    accessExpiration: process.env.JWT_ACCESS_EXPIRATION || '15m',
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  },

  // Encryption
  encryption: {
    secretKey: process.env.ENCRYPTION_KEY,
  },

  // CSRF
  csrf: {
    secretKey: process.env.CSRF_SECRET_KEY,
  },

  argon2: {
    memoryCost: process.env.ARGON2_MEMORY_COST,
    timeCost: process.env.ARGON2_TIME_COST,
    parallelismCost: process.env.ARGON2_PARALLELISM,
    saltLength: process.env.ARGON2_SALT_LENGTH,
  },

  // Rate Limiting
  rateLimit: {
    max: process.env.RATE_LIMIT_MAX || 5,
    ttl: process.env.RATE_LIMIT_TTL,
  },

  // 2FA
  tfa: {
    appName: process.env.TWO_FACTOR_APP_NAME,
    recoveryCodeLength: process.env.TWO_FACTOR_RECOVERY_CODE_LENGTH,
    recoveryCodesCount: process.env.TWO_FACTOR_RECOVERY_CODES_COUNT,
  },

  // Attempt Lockout
  attemptLockout: {
    maxAttempts: process.env.ACCOUNT_LOCKOUT_MAX_ATTEMPTS,
    lockDuration: process.env.ACCOUNT_LOCKOUT_DURATION,
  },
}));
