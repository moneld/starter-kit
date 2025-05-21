import { SetMetadata } from '@nestjs/common';

/**
 * Clé de métadonnée pour les routes nécessitant 2FA
 */
export const REQUIRE_2FA_KEY = 'require2FA';

/**
 * Décorateur pour marquer un endpoint comme nécessitant l'authentification à deux facteurs
 * Usage: @Require2FA() sur une méthode de contrôleur
 */
export const Require2FA = () => SetMetadata(REQUIRE_2FA_KEY, true);
