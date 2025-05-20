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
    // Initialiser les options Argon2 une seule fois au démarrage du service
    this.argon2Options = {
      type: argon2.argon2id,
      memoryCost: this.configService.get('security.argon2.memoryCost'),
      timeCost: this.configService.get('security.argon2.timeCost'),
      parallelism: this.configService.get('security.argon2.parallelismCost'),
      salt: this.configService.get('security.argon2.saltLength'),
    };
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
      throw new ConflictException('Un utilisateur avec cet email existe déjà');
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
      const { password: _, ...userResult } = await this.prisma.user.create({
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
      throw new NotFoundException(`Utilisateur non trouvé avec l'ID: ${id}`);
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
  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    // Vérifier si l'utilisateur existe
    await this.findById(id);

    // Préparer les données de mise à jour
    const updateData = await this.buildUpdateData(updateUserDto);

    try {
      // Mettre à jour l'utilisateur
      const { password: _, ...userResult } = await this.prisma.user.update({
        where: { id },
        data: updateData,
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
   * Construit l'objet de mise à jour à partir du DTO
   */
  private async buildUpdateData(
    updateUserDto: UpdateUserDto,
  ): Promise<Prisma.UserUpdateInput> {
    const updateData: Prisma.UserUpdateInput = {};

    // Ajouter les champs non-null au updateData
    if (updateUserDto.firstName !== undefined) {
      updateData.firstName = updateUserDto.firstName;
    }

    if (updateUserDto.lastName !== undefined) {
      updateData.lastName = updateUserDto.lastName;
    }

    if (updateUserDto.isActive !== undefined) {
      updateData.isActive = updateUserDto.isActive;
    }

    if (updateUserDto.role !== undefined) {
      updateData.role = updateUserDto.role;
    }

    // Traitement spécial pour le mot de passe
    if (updateUserDto.password) {
      updateData.password = await this.hashPassword(updateUserDto.password);
    }

    return updateData;
  }

  /**
   * Supprime un utilisateur
   */
  async remove(id: string): Promise<User> {
    // Vérifier si l'utilisateur existe
    await this.findById(id);

    try {
      // Supprimer l'utilisateur
      const { password: _, ...userResult } = await this.prisma.user.delete({
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
    const verificationToken = await this.prisma.verificationToken.findUnique({
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
      const { password: _, ...userResult } = await this.prisma.$transaction(
        async (prisma) => {
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
        },
      );

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

      this.logger.debug(`Tentatives de connexion réinitialisées: ${userId}`);
    } catch (error) {
      this.logger.error(`Erreur réinitialisation tentatives: ${error.message}`);
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
      const lockoutTime = this.configService.get<number>(
        'security.attemptLockout.lockDuration',
        15,
      );

      // Incrémenter le compteur d'échecs
      const updatedAttempts = user.failedLoginAttempts + 1;

      // Préparer la mise à jour avec le nouveau compteur
      const updateData: Prisma.UserUpdateInput = {
        failedLoginAttempts: updatedAttempts,
      };

      // Vérifier si le seuil est atteint pour verrouiller le compte
      if (updatedAttempts >= maxAttempts) {
        updateData.lockedUntil = addMinutes(new Date(), lockoutTime);
        this.logger.warn(
          `Compte verrouillé: ${userId} jusqu'à: ${updateData.lockedUntil}`,
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
      this.logger.error(`Erreur incrémentation tentatives: ${error.message}`);
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

    // Vérifier si un verrouillage est actif
    if (user.lockedUntil && isBefore(new Date(), user.lockedUntil)) {
      return {
        locked: true,
        unlockTime: user.lockedUntil,
      };
    }

    // Réinitialiser le verrouillage si la période est expirée
    if (user.lockedUntil) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { lockedUntil: null },
      });
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
      this.logger.error(`Erreur changement mot de passe: ${error.message}`);
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
    const passwordResetToken = await this.prisma.passwordResetToken.findUnique({
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
      throw new BadRequestException('Le token de réinitialisation a expiré');
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
      return await argon2.hash(password, this.argon2Options);
    } catch (error) {
      this.logger.error(`Erreur hachage mot de passe: ${error.message}`);
      throw new Error('Erreur lors du hachage du mot de passe');
    }
  }
}
