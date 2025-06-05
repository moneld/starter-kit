import { SecurityAlert } from '../../../common/services/anomaly-detection.service';

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export interface LoginResponse extends AuthTokens {
    requiresTwoFactor?: boolean;
    requiresPasswordChange?: boolean; // Nouveau
    passwordExpiryInfo?: {
        // Nouveau
        expired: boolean;
        message: string;
    };
    passwordExpiryWarning?: {
        // Nouveau
        daysRemaining: number;
        expiresAt: Date;
        message: string;
    };
    securityAlerts?: SecurityAlert[];
    user: {
        id: string;
        email: string;
        firstName: string;
        lastName: string;
        role: string;
    };
}

export interface TwoFactorSecretResponse {
    secret: string;
    qrCodeUrl: string;
}

export interface TwoFactorCodesResponse {
    recoveryCodes: string[];
}

export interface MessageResponse {
    message: string;
}

export interface ValidationErrorResponse {
    statusCode: number;
    message: string[] | string;
    error: string;
}
