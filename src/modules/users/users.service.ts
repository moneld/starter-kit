import {
    BadRequestException,
    ConflictException,
    Injectable,
    Logger,
    NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

import * as argon2 from 'argon2';
import { addHours, addMinutes, isBefore, isPast } from 'date-fns';
import { Prisma, User, UserRole } from 'generated/prisma';
import { v4 as uuidv4 } from 'uuid';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
    private readonly logger = new Logger(UsersService.name);
    private readonly argon2Options: argon2.Options;

    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
    ) {
        // Corriger les options Argon2
        this.argon2Options = {
            type: argon2.argon2id,
            memoryCost: parseInt(
                this.configService.get('security.argon2.memoryCost', '65536'),
                10,
            ),
            timeCost: parseInt(
                this.configService.get('security.argon2.timeCost', '3'),
                10,
            ),
            parallelism: parseInt(
                this.configService.get('security.argon2.parallelismCost', '4'),
                10,
            ),
            // Retirer la propriété 'salt' - elle n'existe pas dans argon2.Options
            // Le sel est généré automatiquement par argon2
        };

        // Vérifier que les valeurs sont valides
        if (
            isNaN(this.argon2Options.memoryCost!) ||
            this.argon2Options.memoryCost! <= 0
        ) {
            this.logger.warn(
                'Configuration Argon2 memoryCost invalide, utilisation de la valeur par défaut',
            );
            this.argon2Options.memoryCost = 65536;
        }

        if (
            isNaN(this.argon2Options.timeCost!) ||
            this.argon2Options.timeCost! <= 0
        ) {
            this.logger.warn(
                'Configuration Argon2 timeCost invalide, utilisation de la valeur par défaut',
            );
            this.argon2Options.timeCost = 3;
        }

        if (
            isNaN(this.argon2Options.parallelism!) ||
            this.argon2Options.parallelism! <= 0
        ) {
            this.logger.warn(
                'Configuration Argon2 parallelism invalide, utilisation de la valeur par défaut',
            );
            this.argon2Options.parallelism = 4;
        }

        this.logger.log(
            `Argon2 configuré avec: memoryCost=${this.argon2Options.memoryCost}, timeCost=${this.argon2Options.timeCost}, parallelism=${this.argon2Options.parallelism}`,
        );
    }

    /**
     * Crée un nouvel utilisateur
     */
    async create(
        createUserDto: CreateUserDto,
        isAdmin = false,
    ): Promise<{ user: User; verificationToken?: string }> {
        const { email, password, firstName, lastName, role } = createUserDto;
        const normalizedEmail = email.toLowerCase();

        // Vérifier si l'email existe déjà
        const existingUser = await this.prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if (existingUser) {
            this.logger.warn(
                `Tentative de création d'un compte avec un email existant: ${normalizedEmail}`,
            );
            throw new ConflictException(
                'Un utilisateur avec cet email existe déjà',
            );
        }

        // Hasher le mot de passe
        const hashedPassword = await this.hashPassword(password);

        // Préparer les données utilisateur
        const userData: Prisma.UserCreateInput = {
            email: normalizedEmail,
            password: hashedPassword,
            firstName,
            lastName,
            role: isAdmin && role ? role : UserRole.USER,
            isActive: isAdmin ? (createUserDto.isActive ?? false) : false,
            isEmailVerified: isAdmin
                ? (createUserDto.isEmailVerified ?? false)
                : false,
        };

        let verificationToken: string | undefined;

        // Générer un token de vérification si l'utilisateur n'est pas vérifié
        if (!userData.isEmailVerified) {
            verificationToken = uuidv4();
            userData.verificationToken = {
                create: {
                    token: verificationToken,
                    expiresAt: addHours(new Date(), 24),
                },
            };
        }

        try {
            // Créer l'utilisateur
            const { password: _, ...userResult } =
                await this.prisma.user.create({
                    data: userData,
                });

            this.logger.log(`Utilisateur créé avec succès: ${normalizedEmail}`);

            return {
                user: userResult as User,
                verificationToken,
            };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la création de l'utilisateur: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Trouve tous les utilisateurs avec pagination et filtrage optionnels
     */
    async findAll(params: {
        skip?: number;
        take?: number;
        orderBy?: Prisma.UserOrderByWithRelationInput;
        where?: Prisma.UserWhereInput;
    }) {
        const { skip, take, orderBy, where } = params;

        try {
            // Utilisation du $transaction pour garantir la cohérence des données
            const [users, total] = await this.prisma.$transaction([
                this.prisma.user.findMany({
                    skip,
                    take,
                    where,
                    orderBy,
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                        isActive: true,
                        isEmailVerified: true,
                        createdAt: true,
                        updatedAt: true,
                        isTwoFactorEnabled: true,
                        lastLoginAt: true,
                    },
                }),
                this.prisma.user.count({ where }),
            ]);

            return { users, total };
        } catch (error) {
            this.logger.error(
                `Erreur lors de la récupération des utilisateurs: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Trouve un utilisateur par ID
     */
    async findById(id: string): Promise<User> {
        const user = await this.prisma.user.findUnique({
            where: { id },
        });

        if (!user) {
            throw new NotFoundException(
                `Utilisateur non trouvé avec l'ID: ${id}`,
            );
        }

        return user;
    }

    /**
     * Trouve un utilisateur par email
     */
    async findByEmail(email: string): Promise<User> {
        const normalizedEmail = email.toLowerCase();

        const user = await this.prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if (!user) {
            throw new NotFoundException(
                `Utilisateur non trouvé avec l'email: ${normalizedEmail}`,
            );
        }

        return user;
    }

    /**
     * Met à jour un utilisateur
     */
    async update(id: string, updateData: Partial<any>): Promise<User> {
        // Vérifier si l'utilisateur existe
        await this.findById(id);

        // Préparer les données de mise à jour
        const updateObj: Prisma.UserUpdateInput = {};

        // Ajouter les champs définis dans updateData au updateObj
        if (updateData.firstName !== undefined) {
            updateObj.firstName = updateData.firstName;
        }

        if (updateData.lastName !== undefined) {
            updateObj.lastName = updateData.lastName;
        }

        if (updateData.email !== undefined) {
            updateObj.email = updateData.email.toLowerCase();
        }

        if (updateData.password !== undefined) {
            updateObj.password = await this.hashPassword(updateData.password);
        }

        if (updateData.role !== undefined) {
            updateObj.role = updateData.role;
        }

        if (updateData.isActive !== undefined) {
            updateObj.isActive = updateData.isActive;
        }

        if (updateData.isEmailVerified !== undefined) {
            updateObj.isEmailVerified = updateData.isEmailVerified;
        }

        if (updateData.failedLoginAttempts !== undefined) {
            updateObj.failedLoginAttempts = updateData.failedLoginAttempts;
        }

        if (updateData.lockedUntil !== undefined) {
            updateObj.lockedUntil = updateData.lockedUntil;
        }

        try {
            // Mettre à jour l'utilisateur
            const { password: _, ...userResult } =
                await this.prisma.user.update({
                    where: { id },
                    data: updateObj,
                });

            this.logger.log(`Utilisateur mis à jour avec succès: ${id}`);
            return userResult as User;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la mise à jour de l'utilisateur: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Supprime un utilisateur
     */
    async remove(id: string): Promise<User> {
        // Vérifier si l'utilisateur existe
        await this.findById(id);

        try {
            // Supprimer l'utilisateur
            const { password: _, ...userResult } =
                await this.prisma.user.delete({
                    where: { id },
                });

            this.logger.log(`Utilisateur supprimé avec succès: ${id}`);
            return userResult as User;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la suppression de l'utilisateur: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Vérifie l'email d'un utilisateur avec le token de vérification
     */
    async verifyEmail(token: string): Promise<User> {
        // Rechercher le token de vérification avec l'utilisateur associé
        const verificationToken =
            await this.prisma.verificationToken.findUnique({
                where: { token },
                include: { user: true },
            });

        if (!verificationToken) {
            throw new NotFoundException('Token de vérification invalide');
        }

        // Vérifier si le token n'a pas expiré
        if (isPast(verificationToken.expiresAt)) {
            // Supprimer le token expiré et informer l'utilisateur
            await this.prisma.verificationToken.delete({
                where: { id: verificationToken.id },
            });

            throw new BadRequestException('Le token de vérification a expiré');
        }

        try {
            // Transaction pour garantir l'atomicité des opérations
            const { password: _, ...userResult } =
                await this.prisma.$transaction(async (prisma) => {
                    // Supprimer le token de vérification
                    await prisma.verificationToken.delete({
                        where: { id: verificationToken.id },
                    });

                    // Mettre à jour l'utilisateur
                    return await prisma.user.update({
                        where: { id: verificationToken.userId },
                        data: {
                            isEmailVerified: true,
                            isActive: true,
                        },
                    });
                });

            this.logger.log(
                `Email vérifié avec succès pour l'utilisateur: ${verificationToken.userId}`,
            );
            return userResult as User;
        } catch (error) {
            this.logger.error(
                `Erreur lors de la vérification de l'email: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Réinitialise le compteur d'échecs de connexion
     */
    async resetLoginAttempts(userId: string): Promise<void> {
        try {
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    failedLoginAttempts: 0,
                    lockedUntil: null,
                    lastLoginAt: new Date(),
                },
            });

            this.logger.debug(
                `Tentatives de connexion réinitialisées: ${userId}`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur réinitialisation tentatives: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Incrémente le compteur d'échecs de connexion et verrouille le compte si nécessaire
     */
    async incrementLoginAttempts(userId: string): Promise<void> {
        try {
            const user = await this.findById(userId);
            const maxAttempts = this.configService.get<number>(
                'security.attemptLockout.maxAttempts',
                5,
            );

            // Corriger la récupération de la durée de verrouillage
            const lockoutDurationStr = this.configService.get<string>(
                'security.attemptLockout.lockDuration',
                '15m',
            );

            // Parser la durée de verrouillage (ex: "15m", "1h", "30")
            let lockoutMinutes = 15; // valeur par défaut

            if (lockoutDurationStr) {
                // Vérifier si c'est un nombre simple (en minutes)
                const numericValue = parseInt(lockoutDurationStr, 10);
                if (!isNaN(numericValue)) {
                    lockoutMinutes = numericValue;
                } else {
                    // Parser les formats comme "15m", "1h", etc.
                    const match = lockoutDurationStr.match(/^(\d+)([mh])?$/i);
                    if (match) {
                        const value = parseInt(match[1], 10);
                        const unit = match[2]?.toLowerCase() || 'm';

                        if (unit === 'h') {
                            lockoutMinutes = value * 60; // convertir heures en minutes
                        } else {
                            lockoutMinutes = value; // déjà en minutes
                        }
                    } else {
                        this.logger.warn(
                            `Format de durée de verrouillage invalide: ${lockoutDurationStr}, utilisation de 15 minutes par défaut`,
                        );
                    }
                }
            }

            // Incrémenter le compteur d'échecs
            const updatedAttempts = user.failedLoginAttempts + 1;

            // Préparer la mise à jour avec le nouveau compteur
            const updateData: Prisma.UserUpdateInput = {
                failedLoginAttempts: updatedAttempts,
            };

            // Vérifier si le seuil est atteint pour verrouiller le compte
            if (updatedAttempts >= maxAttempts) {
                const lockUntilDate = addMinutes(new Date(), lockoutMinutes);

                // Vérifier que la date est valide
                if (isNaN(lockUntilDate.getTime())) {
                    this.logger.error(
                        `Date de verrouillage invalide calculée avec ${lockoutMinutes} minutes`,
                    );
                    // Utiliser une valeur par défaut de 15 minutes
                    updateData.lockedUntil = addMinutes(new Date(), 15);
                } else {
                    updateData.lockedUntil = lockUntilDate;
                }

                this.logger.warn(
                    `Compte verrouillé: ${userId} jusqu'à: ${updateData.lockedUntil?.toISOString()}`,
                );
            } else {
                this.logger.debug(
                    `Échec connexion: ${userId}, ${updatedAttempts}/${maxAttempts}`,
                );
            }

            // Mise à jour de l'utilisateur
            await this.prisma.user.update({
                where: { id: userId },
                data: updateData,
            });
        } catch (error) {
            this.logger.error(
                `Erreur incrémentation tentatives: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Vérifie si un compte est verrouillé
     */
    async isAccountLocked(
        userId: string,
    ): Promise<{ locked: boolean; unlockTime?: Date }> {
        const user = await this.findById(userId);

        // Si aucun verrouillage n'est défini, le compte n'est pas verrouillé
        if (!user.lockedUntil) {
            return { locked: false };
        }

        // Convertir lockedUntil en objet Date si c'est une chaîne
        const lockUntilDate =
            user.lockedUntil instanceof Date
                ? user.lockedUntil
                : new Date(user.lockedUntil);

        const now = new Date();

        // Ajouter des logs pour déboguer
        this.logger.debug(`Vérification verrouillage pour ${userId}:`);
        this.logger.debug(
            `- Date de déverrouillage: ${lockUntilDate.toISOString()}`,
        );
        this.logger.debug(`- Date actuelle: ${now.toISOString()}`);
        this.logger.debug(
            `- Comparaison (lockUntilDate > now): ${lockUntilDate > now}`,
        );
        this.logger.debug(
            `- Temps restant en minutes: ${(lockUntilDate.getTime() - now.getTime()) / (1000 * 60)}`,
        );

        // Vérifier si un verrouillage est actif
        if (lockUntilDate > now) {
            // Le compte est verrouillé si lockedUntil est dans le futur
            this.logger.warn(
                `Compte verrouillé: ${userId} jusqu'à ${lockUntilDate.toISOString()}`,
            );
            return {
                locked: true,
                unlockTime: lockUntilDate,
            };
        }

        // La période de verrouillage est expirée, nettoyer le champ
        this.logger.log(
            `Nettoyage du verrouillage expiré pour l'utilisateur: ${userId}`,
        );

        try {
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    lockedUntil: null,
                    failedLoginAttempts: 0, // Réinitialiser aussi les tentatives
                },
            });

            this.logger.log(
                `Verrouillage expiré nettoyé pour l'utilisateur: ${userId}`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors du nettoyage du verrouillage expiré: ${error.message}`,
            );
            // Continuer même si le nettoyage échoue
        }

        return { locked: false };
    }

    /**
     * Change le mot de passe d'un utilisateur
     */
    async changePassword(userId: string, newPassword: string): Promise<void> {
        try {
            // Hacher le nouveau mot de passe
            const hashedPassword = await this.hashPassword(newPassword);

            await this.prisma.$transaction(async (prisma) => {
                // Mettre à jour le mot de passe
                await prisma.user.update({
                    where: { id: userId },
                    data: {
                        password: hashedPassword,
                    },
                });

                // Supprimer tous les refresh tokens
                await prisma.refreshToken.deleteMany({
                    where: { userId },
                });
            });

            this.logger.log(`Mot de passe changé avec succès: ${userId}`);
        } catch (error) {
            this.logger.error(
                `Erreur changement mot de passe: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Crée un token de réinitialisation de mot de passe
     */
    async createPasswordResetToken(email: string): Promise<string> {
        const user = await this.findByEmail(email);
        const token = uuidv4();
        const expirationMinutes = 60;
        const expiresAt = addMinutes(new Date(), expirationMinutes);

        try {
            // Upsert du token de réinitialisation
            await this.prisma.passwordResetToken.upsert({
                where: { userId: user.id },
                create: {
                    token,
                    expiresAt,
                    userId: user.id,
                },
                update: {
                    token,
                    expiresAt,
                },
            });

            this.logger.log(`Token de réinitialisation créé: ${email}`);
            return token;
        } catch (error) {
            this.logger.error(
                `Erreur création token réinitialisation: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Réinitialise le mot de passe avec un token
     */
    async resetPassword(token: string, newPassword: string): Promise<void> {
        // Rechercher le token avec l'utilisateur associé
        const passwordResetToken =
            await this.prisma.passwordResetToken.findUnique({
                where: { token },
                include: { user: true },
            });

        if (!passwordResetToken) {
            throw new NotFoundException('Token de réinitialisation invalide');
        }

        // Vérifier si le token n'a pas expiré
        if (isPast(passwordResetToken.expiresAt)) {
            await this.prisma.passwordResetToken.delete({
                where: { id: passwordResetToken.id },
            });
            throw new BadRequestException(
                'Le token de réinitialisation a expiré',
            );
        }

        try {
            // Hacher le nouveau mot de passe
            const hashedPassword = await this.hashPassword(newPassword);

            await this.prisma.$transaction(async (prisma) => {
                // Mettre à jour le mot de passe et supprimer le token
                await prisma.user.update({
                    where: { id: passwordResetToken.userId },
                    data: {
                        password: hashedPassword,
                    },
                });

                // Supprimer le token de réinitialisation
                await prisma.passwordResetToken.delete({
                    where: { id: passwordResetToken.id },
                });

                // Supprimer tous les refresh tokens
                await prisma.refreshToken.deleteMany({
                    where: { userId: passwordResetToken.userId },
                });
            });

            this.logger.log(
                `Mot de passe réinitialisé: ${passwordResetToken.userId}`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur réinitialisation mot de passe: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Hash un mot de passe avec Argon2
     */
    private async hashPassword(password: string): Promise<string> {
        try {
            // Ajouter une validation du mot de passe avant le hachage
            if (
                !password ||
                typeof password !== 'string' ||
                password.trim().length === 0
            ) {
                throw new Error('Le mot de passe ne peut pas être vide');
            }

            this.logger.debug('Hachage du mot de passe avec Argon2');
            const hashedPassword = await argon2.hash(
                password,
                this.argon2Options,
            );
            this.logger.debug('Mot de passe haché avec succès');

            return hashedPassword;
        } catch (error) {
            this.logger.error(
                `Erreur lors du hachage du mot de passe: ${error.message}`,
            );
            this.logger.error(
                `Options Argon2 utilisées: ${JSON.stringify(this.argon2Options)}`,
            );

            // Essayer un hachage plus simple en cas d'erreur
            try {
                this.logger.debug(
                    'Tentative de hachage avec les options par défaut',
                );
                return await argon2.hash(password, {
                    type: argon2.argon2id,
                    memoryCost: 65536,
                    timeCost: 3,
                    parallelism: 4,
                });
            } catch (fallbackError) {
                this.logger.error(
                    `Erreur lors du hachage de fallback: ${fallbackError.message}`,
                );
                throw new Error('Impossible de hacher le mot de passe');
            }
        }
    }
}
