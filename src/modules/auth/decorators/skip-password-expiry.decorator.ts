import { SetMetadata } from '@nestjs/common';

export const SKIP_PASSWORD_EXPIRY_KEY = 'skipPasswordExpiry';

/**
 * Décorateur pour ignorer la vérification d'expiration du mot de passe
 * Utile pour les endpoints de changement de mot de passe
 */
export const SkipPasswordExpiry = () =>
    SetMetadata(SKIP_PASSWORD_EXPIRY_KEY, true);
