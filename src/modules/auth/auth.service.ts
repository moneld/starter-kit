import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { CryptoService } from '../../common/services/crypto.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { TwoFactorAuthDto } from './dto/two-factor-auth.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { RecoveryCodeDto } from './dto/recovery-code.dto';
import { User } from 'generated/prisma';
import * as argon2 from 'argon2';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';
import { addDays } from 'date-fns';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly cryptoService: CryptoService,
  ) {
    // Configurer les options d'authentificateur
    authenticator.options = {
      step: 30, // Période de validité en secondes
      window: 1, // Fenêtre de tolérance pour le délai
    };
  }

  /**
   * Enregistre un nouvel utilisateur
   */
  async register(registerDto: RegisterDto): Promise<{ message: string }> {
    // Vérifier que les mots de passe correspondent
    if (registerDto.password !== registerDto.passwordConfirm) {
      throw new BadRequestException('Les mots de passe ne correspondent pas');
    }

    try {
      // Créer un nouvel utilisateur
      const { user, verificationToken } = await this.usersService.create({
        email: registerDto.email,
        password: registerDto.password,
        firstName: registerDto.firstName,
        lastName: registerDto.lastName,
      });

      // Envoyer un email de vérification (à implémenter)
      if (verificationToken) {
        await this.sendVerificationEmail(user.email, verificationToken);
      }

      return {
        message: 'Inscription réussie. Veuillez vérifier votre email pour activer votre compte.'
      };
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      this.logger.error(`Erreur lors de l'inscription: ${error.message}`);
      throw new BadRequestException('Erreur lors de l\'inscription');
    }
  }

  /**
   * Connecte un utilisateur
   */
  async login(loginDto: LoginDto): Promise<{
    accessToken: string;
    refreshToken: string;
    requiresTwoFactor?: boolean;
    user: {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      role: string;
    };
  }> {
    try {
      // Trouver l'utilisateur par email
      const user = await this.usersService.findByEmail(loginDto.email);

      // Vérifier si le compte est verrouillé
      const { locked, unlockTime } = await this.usersService.isAccountLocked(user.id);
      if (locked) {
        throw new ForbiddenException(
          `Compte verrouillé. Réessayez après ${unlockTime.toLocaleString()}`
        );
      }

      // Vérifier si le compte est actif et vérifié
      if (!user.isActive) {
        throw new UnauthorizedException('Compte inactif');
      }

      if (!user.isEmailVerified) {
        throw new UnauthorizedException('Email non vérifié');
      }

      // Vérifier le mot de passe
      const isPasswordValid = await this.validatePassword(
        loginDto.password,
        user.password
      );

      if (!isPasswordValid) {
        // Incrémenter le compteur d'échecs de connexion
        await this.usersService.incrementLoginAttempts(user.id);
        throw new UnauthorizedException('Identifiants invalides');
      }

      // Réinitialiser le compteur d'échecs de connexion
      await this.usersService.resetLoginAttempts(user.id);

      // Vérifier si l'authentification à deux facteurs est activée
      if (user.isTwoFactorEnabled) {
        // Générer un token JWT spécial pour l'authentification 2FA
        const tfaToken = await this.generateTwoFactorToken(user);

        return {
          accessToken: tfaToken,
          refreshToken: '', // Pas de refresh token avant la 2FA complète
          requiresTwoFactor: true,
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
          }
        };
      }

      // Générer les tokens
      const tokens = await this.generateTokens(user);

      // Créer un refresh token en base de données
      await this.saveRefreshToken(user.id, tokens.refreshToken);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
        }
      };
    } catch (error) {
      if (error instanceof UnauthorizedException ||
        error instanceof ForbiddenException) {
        throw error;
      }
      this.logger.error(`Erreur lors de la connexion: ${error.message}`);
      throw new UnauthorizedException('Erreur lors de la connexion');
    }
  }

  /**
   * Valide un code d'authentification à deux facteurs
   */
  async verifyTwoFactorAuth(userId: string, twoFactorAuthDto: TwoFactorAuthDto): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const user = await this.usersService.findById(userId);

    if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
      throw new BadRequestException('L\'authentification à deux facteurs n\'est pas activée');
    }

    // Déchiffrer le secret 2FA
    const decryptedSecret = this.cryptoService.decrypt(user.twoFactorSecret);

    // Vérifier le code 2FA
    const isCodeValid = authenticator.verify({
      token: twoFactorAuthDto.twoFactorCode,
      secret: decryptedSecret,
    });

    if (!isCodeValid) {
      throw new UnauthorizedException('Code d\'authentification à deux facteurs invalide');
    }

    // Générer les tokens avec 2FA complète
    const tokens = await this.generateTokens(user, true);

    // Créer un refresh token en base de données
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  /**
   * Valide un code de récupération d'urgence
   */
  async verifyRecoveryCode(userId: string, recoveryCodeDto: RecoveryCodeDto): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const user = await this.usersService.findById(userId);

    if (!user.isTwoFactorEnabled || !user.twoFactorRecoveryCodes) {
      throw new BadRequestException('L\'authentification à deux facteurs n\'est pas activée');
    }

    // Déchiffrer les codes de récupération
    const decryptedCodes = this.cryptoService.decrypt(user.twoFactorRecoveryCodes);
    const recoveryCodes = JSON.parse(decryptedCodes) as string[];

    // Vérifier si le code de récupération est valide
    const codeIndex = recoveryCodes.indexOf(recoveryCodeDto.recoveryCode);
    if (codeIndex === -1) {
      throw new UnauthorizedException('Code de récupération invalide');
    }

    // Supprimer le code utilisé
    recoveryCodes.splice(codeIndex, 1);

    // Mettre à jour les codes de récupération
    const updatedEncryptedCodes = this.cryptoService.encrypt(JSON.stringify(recoveryCodes));
    await this.prisma.user.update({
      where: { id: user.id },
      data: { twoFactorRecoveryCodes: updatedEncryptedCodes },
    });

    // Générer les tokens avec 2FA complète
    const tokens = await this.generateTokens(user, true);

    // Créer un refresh token en base de données
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  /**
   * Active l'authentification à deux facteurs
   */
  async generateTwoFactorSecret(userId: string): Promise<{
    secret: string;
    qrCodeUrl: string;
  }> {
    const user = await this.usersService.findById(userId);

    // Générer un nouveau secret
    const appName = this.configService.get<string>('security.tfa.appName', 'MyApp');
    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, appName, secret);

    // Générer le QR code
    const qrCodeUrl = await qrcode.toDataURL(otpAuthUrl);

    return {
      secret,
      qrCodeUrl,
    };
  }

  /**
   * Vérifie et active l'authentification à deux facteurs
   */
  async enableTwoFactorAuth(userId: string, verifyTwoFactorDto: VerifyTwoFactorDto): Promise<{
    recoveryCodes: string[];
  }> {
    const { secret, code } = verifyTwoFactorDto;

    // Vérifier si le code est valide
    const isCodeValid = authenticator.verify({
      token: code,
      secret,
    });

    if (!isCodeValid) {
      throw new UnauthorizedException('Code d\'authentification invalide');
    }

    // Générer des codes de récupération
    const recoveryCodes = await this.generateRecoveryCodes();

    // Chiffrer le secret et les codes de récupération
    const encryptedSecret = this.cryptoService.encrypt(secret);
    const encryptedRecoveryCodes = this.cryptoService.encrypt(JSON.stringify(recoveryCodes));

    // Activer 2FA pour l'utilisateur
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        isTwoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        twoFactorRecoveryCodes: encryptedRecoveryCodes,
      },
    });

    return { recoveryCodes };
  }

  /**
   * Désactive l'authentification à deux facteurs
   */
  async disableTwoFactorAuth(userId: string, password: string): Promise<void> {
    const user = await this.usersService.findById(userId);

    // Vérifier le mot de passe
    const isPasswordValid = await this.validatePassword(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Mot de passe invalide');
    }

    // Désactiver 2FA
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        isTwoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorRecoveryCodes: null,
      },
    });
  }

  /**
   * Régénère les codes de récupération
   */
  async regenerateRecoveryCodes(userId: string, password: string): Promise<{
    recoveryCodes: string[]
  }> {
    const user = await this.usersService.findById(userId);

    // Vérifier si 2FA est activée
    if (!user.isTwoFactorEnabled) {
      throw new BadRequestException('L\'authentification à deux facteurs n\'est pas activée');
    }

    // Vérifier le mot de passe
    const isPasswordValid = await this.validatePassword(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Mot de passe invalide');
    }

    // Générer de nouveaux codes de récupération
    const recoveryCodes = await this.generateRecoveryCodes();
    const encryptedRecoveryCodes = this.cryptoService.encrypt(JSON.stringify(recoveryCodes));

    // Mettre à jour les codes de récupération
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorRecoveryCodes: encryptedRecoveryCodes,
      },
    });

    return { recoveryCodes };
  }

  /**
   * Rafraîchit le token d'accès avec un token de rafraîchissement
   */
  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const { refreshToken } = refreshTokenDto;

      // Vérifier si le token existe et n'est pas révoqué
      const tokenRecord = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken },
        include: { user: true },
      });

      if (!tokenRecord || tokenRecord.isRevoked) {
        throw new UnauthorizedException('Token de rafraîchissement invalide');
      }

      // Vérifier si le token n'a pas expiré
      if (new Date() > tokenRecord.expiresAt) {
        await this.prisma.refreshToken.delete({ where: { id: tokenRecord.id } });
        throw new UnauthorizedException('Token de rafraîchissement expiré');
      }

      // Vérifier si l'utilisateur est actif
      if (!tokenRecord.user.isActive) {
        throw new UnauthorizedException('Compte inactif');
      }

      // Générer de nouveaux tokens
      const tokens = await this.generateTokens(tokenRecord.user, tokenRecord.user.isTwoFactorEnabled);

      // Mettre à jour le token de rafraîchissement
      await this.prisma.$transaction([
        this.prisma.refreshToken.delete({ where: { id: tokenRecord.id } }),
        this.prisma.refreshToken.create({
          data: {
            token: tokens.refreshToken,
            expiresAt: addDays(new Date(), 7),
            userAgent: tokenRecord.userAgent,
            ipAddress: tokenRecord.ipAddress,
            userId: tokenRecord.user.id,
          },
        }),
      ]);

      return tokens;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      this.logger.error(`Erreur lors du rafraîchissement du token: ${error.message}`);
      throw new UnauthorizedException('Erreur lors du rafraîchissement du token');
    }
  }

  /**
   * Déconnecte un utilisateur en révoquant son token de rafraîchissement
   */
  async logout(refreshToken: string): Promise<void> {
    try {
      const token = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken },
      });

      if (token) {
        await this.prisma.refreshToken.delete({
          where: { id: token.id },
        });
      }
    } catch (error) {
      this.logger.error(`Erreur lors de la déconnexion: ${error.message}`);
      // Ne pas propager l'erreur, la déconnexion doit toujours "réussir"
    }
  }

  /**
   * Déconnecte un utilisateur de toutes ses sessions
   */
  async logoutAll(userId: string): Promise<void> {
    try {
      await this.prisma.refreshToken.deleteMany({
        where: { userId },
      });
    } catch (error) {
      this.logger.error(`Erreur lors de la déconnexion globale: ${error.message}`);
      throw new Error('Erreur lors de la déconnexion de toutes les sessions');
    }
  }

  /**
   * Demande de réinitialisation de mot de passe
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
    try {
      const { email } = forgotPasswordDto;

      // Vérifier si l'utilisateur existe
      let user;
      try {
        user = await this.usersService.findByEmail(email);
      } catch (error) {
        // Ne pas divulguer si l'email existe ou non pour des raisons de sécurité
        return {
          message: 'Si votre email est enregistré, vous recevrez un lien de réinitialisation.'
        };
      }

      // Créer un token de réinitialisation
      const resetToken = await this.usersService.createPasswordResetToken(email);

      // Envoyer un email avec le lien de réinitialisation (à implémenter)
      await this.sendPasswordResetEmail(email, resetToken);

      return {
        message: 'Si votre email est enregistré, vous recevrez un lien de réinitialisation.'
      };
    } catch (error) {
      this.logger.error(`Erreur lors de la demande de réinitialisation: ${error.message}`);
      return {
        message: 'Si votre email est enregistré, vous recevrez un lien de réinitialisation.'
      };
    }
  }

  /**
   * Réinitialise le mot de passe avec un token
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    // Vérifier que les mots de passe correspondent
    if (resetPasswordDto.password !== resetPasswordDto.passwordConfirm) {
      throw new BadRequestException('Les mots de passe ne correspondent pas');
    }

    try {
      // Réinitialiser le mot de passe
      await this.usersService.resetPassword(
        resetPasswordDto.token,
        resetPasswordDto.password
      );

      return { message: 'Mot de passe réinitialisé avec succès' };
    } catch (error) {
      if (error instanceof NotFoundException ||
        error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Erreur lors de la réinitialisation: ${error.message}`);
      throw new BadRequestException('Erreur lors de la réinitialisation du mot de passe');
    }
  }

  /**
   * Change le mot de passe d'un utilisateur connecté
   */
  async changePassword(userId: string, changePasswordDto: ChangePasswordDto): Promise<{
    message: string
  }> {
    // Vérifier que les mots de passe correspondent
    if (changePasswordDto.newPassword !== changePasswordDto.newPasswordConfirm) {
      throw new BadRequestException('Les nouveaux mots de passe ne correspondent pas');
    }

    try {
      const user = await this.usersService.findById(userId);

      // Vérifier l'ancien mot de passe
      const isPasswordValid = await this.validatePassword(
        changePasswordDto.currentPassword,
        user.password
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Mot de passe actuel invalide');
      }

      // Changer le mot de passe
      await this.usersService.changePassword(userId, changePasswordDto.newPassword);

      // Déconnecter toutes les sessions
      await this.logoutAll(userId);

      return { message: 'Mot de passe changé avec succès' };
    } catch (error) {
      if (error instanceof UnauthorizedException ||
        error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Erreur lors du changement de mot de passe: ${error.message}`);
      throw new BadRequestException('Erreur lors du changement de mot de passe');
    }
  }

  /**
   * Vérifie un email avec un token
   */
  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      await this.usersService.verifyEmail(token);
      return { message: 'Email vérifié avec succès' };
    } catch (error) {
      if (error instanceof NotFoundException ||
        error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error(`Erreur lors de la vérification d'email: ${error.message}`);
      throw new BadRequestException('Erreur lors de la vérification de l\'email');
    }
  }

  /**
   * Renvoie un email de vérification
   */
  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    try {
      // Trouver l'utilisateur
      const user = await this.usersService.findByEmail(email);

      // Vérifier si l'email est déjà vérifié
      if (user.isEmailVerified) {
        return { message: 'Votre email est déjà vérifié' };
      }

      // Récupérer ou créer un nouveau token de vérification
      let verificationToken = await this.prisma.verificationToken.findUnique({
        where: { userId: user.id },
      });

      if (!verificationToken) {
        // Créer un nouveau token de vérification
        const token = uuidv4();
        verificationToken = await this.prisma.verificationToken.create({
          data: {
            token,
            expiresAt: addDays(new Date(), 1),
            userId: user.id,
          },
        });
      }

      // Envoyer l'email de vérification
      await this.sendVerificationEmail(email, verificationToken.token);

      return {
        message: 'Email de vérification envoyé. Veuillez vérifier votre boîte de réception.'
      };
    } catch (error) {
      this.logger.error(`Erreur lors de l'envoi de l'email de vérification: ${error.message}`);
      return {
        message: 'Si votre email est enregistré, vous recevrez un email de vérification.'
      };
    }
  }

  /**
   * Valide un mot de passe avec Argon2
   */
  private async validatePassword(
    plainPassword: string,
    hashedPassword: string
  ): Promise<boolean> {
    try {
      return await argon2.verify(hashedPassword, plainPassword);
    } catch (error) {
      this.logger.error(`Erreur lors de la validation du mot de passe: ${error.message}`);
      return false;
    }
  }

  /**
   * Génère un token JWT pour l'authentification à deux facteurs
   */
  private async generateTwoFactorToken(user: User): Promise<string> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      isTwoFactorAuth: false, // Token spécial pour 2FA en attente
    };

    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('security.jwt.accessSecret'),
      expiresIn: '15m', // Courte durée pour la validation 2FA
    });
  }

  /**
   * Génère les tokens JWT d'accès et de rafraîchissement
   */
  private async generateTokens(
    user: User,
    isTwoFactorAuthenticated = false
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
    };

    // Ajouter l'info de 2FA si nécessaire
    if (user.isTwoFactorEnabled) {
      payload.isTwoFactorAuth = isTwoFactorAuthenticated;
    }

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.sign(payload, {
        secret: this.configService.get<string>('security.jwt.accessSecret'),
        expiresIn: this.configService.get<string>('security.jwt.accessExpiration'),
      }),
      this.jwtService.sign(payload, {
        secret: this.configService.get<string>('security.jwt.refreshSecret'),
        expiresIn: this.configService.get<string>('security.jwt.refreshExpiration'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Sauvegarde un token de rafraîchissement en base de données
   */
  private async saveRefreshToken(
    userId: string,
    token: string,
    userAgent?: string,
    ipAddress?: string
  ): Promise<void> {
    try {
      // Supprimer l'ancien refresh token s'il existe
      await this.prisma.refreshToken.deleteMany({
        where: { userId },
      });

      // Créer un nouveau refresh token
      await this.prisma.refreshToken.create({
        data: {
          token,
          expiresAt: addDays(
            new Date(),
            parseInt(this.configService.get<string>('security.jwt.refreshExpiration', '7d'))
          ),
          userAgent,
          ipAddress,
          userId,
        },
      });
    } catch (error) {
      this.logger.error(`Erreur lors de l'enregistrement du refresh token: ${error.message}`);
      throw new Error('Erreur lors de l\'enregistrement du refresh token');
    }
  }

  /**
   * Génère des codes de récupération pour 2FA
   */
  private async generateRecoveryCodes(): Promise<string[]> {
    const recoveryCodesCount = parseInt(
      this.configService.get<string>('security.tfa.recoveryCodesCount', '8')
    );
    const recoveryCodeLength = parseInt(
      this.configService.get<string>('security.tfa.recoveryCodeLength', '10')
    );

    const recoveryCodes: string[] = [];
    for (let i = 0; i < recoveryCodesCount; i++) {
      recoveryCodes.push(this.cryptoService.generateSecureToken(recoveryCodeLength));
    }

    return recoveryCodes;
  }

  /**
   * Envoie un email de vérification
   * Note: Implémentation fictive, à adapter selon votre système d'envoi d'emails
   */
  private async sendVerificationEmail(
    email: string,
    token: string
  ): Promise<void> {
    // Récupérer l'URL frontend depuis la config
    const frontendUrl = this.configService.get<string>('app.general.frontendUrl');
    const verificationUrl = `${frontendUrl}/auth/verify-email?token=${token}`;

    this.logger.debug(`Email de vérification envoyé à ${email} avec URL: ${verificationUrl}`);

    // Implémenter l'envoi d'email ici
    // (utiliser @nestjs-modules/mailer par exemple)
  }

  /**
   * Envoie un email de réinitialisation de mot de passe
   * Note: Implémentation fictive, à adapter selon votre système d'envoi d'emails
   */
  private async sendPasswordResetEmail(
    email: string,
    token: string
  ): Promise<void> {
    // Récupérer l'URL frontend depuis la config
    const frontendUrl = this.configService.get<string>('app.general.frontendUrl');
    const resetUrl = `${frontendUrl}/auth/reset-password?token=${token}`;

    this.logger.debug(`Email de réinitialisation envoyé à ${email} avec URL: ${resetUrl}`);

    // Implémenter l'envoi d'email ici
    // (utiliser @nestjs-modules/mailer par exemple)
  }
}