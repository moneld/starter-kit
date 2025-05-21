import { SetMetadata } from '@nestjs/common';

/**
 * Clé de métadonnée pour les routes publiques
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Décorateur pour marquer un endpoint comme public (sans authentification)
 * Usage: @Public() sur une méthode de contrôleur
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
