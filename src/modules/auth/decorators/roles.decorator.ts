import { SetMetadata } from '@nestjs/common';
import { UserRole } from 'generated/prisma';

/**
 * Clé de métadonnée pour les rôles utilisateur
 */
export const ROLES_KEY = 'roles';

/**
 * Décorateur pour restreindre un endpoint à certains rôles
 * Usage: @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN) sur une méthode de contrôleur
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
