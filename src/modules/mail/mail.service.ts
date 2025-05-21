import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as handlebars from 'handlebars';
import * as nodemailer from 'nodemailer';
import * as path from 'path';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    // Création du transporteur Nodemailer
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('app.mail.host'),
      port: this.configService.get<number>('app.mail.port'),
      secure:
        this.configService.get<string>('app.mail.encryption') === 'ssl',
      auth: {
        user: this.configService.get<string>('app.mail.auth.user'),
        pass: this.configService.get<string>('app.mail.auth.pass'),
      },
    });

    // Vérifier la connexion en environnement de développement
    if (
      this.configService.get<string>('app.general.nodeEnv') ===
      'development'
    ) {
      this.verifyConnection();
    }
  }

  /**
   * Vérifie la connexion SMTP
   */
  private async verifyConnection() {
    try {
      await this.transporter.verify();
      this.logger.log('Connexion SMTP vérifiée avec succès');
    } catch (error) {
      this.logger.error(`Erreur de connexion SMTP: ${error.message}`);
    }
  }

  /**
   * Compile un template Handlebars avec les données fournies
   */
  private compileTemplate(templatePath: string, data: any): string {
    try {
      // En production, les templates seraient chargés à partir du système de fichiers
      // Pour simplifier, nous allons utiliser des templates en ligne
      const templateContent = fs.readFileSync(templatePath, 'utf-8');
      const template = handlebars.compile(templateContent);
      return template(data);
    } catch (error) {
      this.logger.error(
        `Erreur de compilation du template: ${error.message}`,
      );
      // Template de secours en cas d'erreur
      return `<h1>${data.subject || 'Notification'}</h1><p>${data.text || "Veuillez consulter notre site pour plus d'informations."}</p>`;
    }
  }

  /**
   * Envoie un email
   */
  async sendMail(options: {
    to: string;
    subject: string;
    template?: string;
    context?: any;
    text?: string;
    html?: string;
  }): Promise<boolean> {
    try {
      const { to, subject, template, context, text, html } = options;

      let htmlContent = html;

      // Si un template est spécifié, le compiler
      if (template && context) {
        const templatePath = path.join(
          process.cwd(),
          'templates',
          `${template}.hbs`,
        );
        htmlContent = this.compileTemplate(templatePath, context);
      }

      // Envoyer l'email
      await this.transporter.sendMail({
        from: this.configService.get<string>('app.mail.from'),
        to,
        subject,
        text: text || '',
        html: htmlContent || '',
      });

      this.logger.log(`Email envoyé à ${to} : ${subject}`);
      return true;
    } catch (error) {
      this.logger.error(`Erreur d'envoi d'email: ${error.message}`);
      return false;
    }
  }

  /**
   * Envoie un email de vérification
   */
  async sendVerificationEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean> {
    const frontendUrl = this.configService.get<string>(
      'app.general.frontendUrl',
    );
    const verificationUrl = `${frontendUrl}/auth/verify-email?token=${token}`;
    const appName = this.configService.get<string>(
      'app.general.name',
      'Notre Application',
    );

    return await this.sendMail({
      to: email,
      subject: `Vérification de votre compte ${appName}`,
      text: `Bonjour ${userName || ''},\n\nMerci de vous être inscrit sur ${appName}. Veuillez cliquer sur le lien suivant pour vérifier votre adresse email :\n\n${verificationUrl}\n\nCe lien expirera dans 24 heures.\n\nCordialement,\nL'équipe ${appName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Vérification de votre adresse email</h2>
          <p>Bonjour ${userName || ''},</p>
          <p>Merci de vous être inscrit sur ${appName}. Veuillez cliquer sur le bouton ci-dessous pour vérifier votre adresse email :</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Vérifier mon email</a>
          </p>
          <p>Si le bouton ne fonctionne pas, vous pouvez également copier et coller le lien suivant dans votre navigateur :</p>
          <p style="word-break: break-all;">${verificationUrl}</p>
          <p>Ce lien expirera dans 24 heures.</p>
          <p>Cordialement,<br>L'équipe ${appName}</p>
        </div>
      `,
    });
  }

  /**
   * Envoie un email de réinitialisation de mot de passe
   */
  async sendPasswordResetEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean> {
    const frontendUrl = this.configService.get<string>(
      'app.general.frontendUrl',
    );
    const resetUrl = `${frontendUrl}/auth/reset-password?token=${token}`;
    const appName = this.configService.get<string>(
      'app.general.name',
      'Notre Application',
    );

    return await this.sendMail({
      to: email,
      subject: `Réinitialisation de votre mot de passe ${appName}`,
      text: `Bonjour ${userName || ''},\n\nNous avons reçu une demande de réinitialisation de mot de passe pour votre compte. Veuillez cliquer sur le lien suivant pour réinitialiser votre mot de passe :\n\n${resetUrl}\n\nCe lien expirera dans 1 heure.\n\nSi vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email et votre mot de passe restera inchangé.\n\nCordialement,\nL'équipe ${appName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Réinitialisation de votre mot de passe</h2>
          <p>Bonjour ${userName || ''},</p>
          <p>Nous avons reçu une demande de réinitialisation de mot de passe pour votre compte. Veuillez cliquer sur le bouton ci-dessous pour réinitialiser votre mot de passe :</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #2196F3; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Réinitialiser mon mot de passe</a>
          </p>
          <p>Si le bouton ne fonctionne pas, vous pouvez également copier et coller le lien suivant dans votre navigateur :</p>
          <p style="word-break: break-all;">${resetUrl}</p>
          <p>Ce lien expirera dans 1 heure.</p>
          <p>Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email et votre mot de passe restera inchangé.</p>
          <p>Cordialement,<br>L'équipe ${appName}</p>
        </div>
      `,
    });
  }

  /**
   * Envoie un email de bienvenue après vérification
   */
  async sendWelcomeEmail(email: string, userName?: string): Promise<boolean> {
    const appName = this.configService.get<string>(
      'app.general.name',
      'Notre Application',
    );
    const frontendUrl = this.configService.get<string>(
      'app.general.frontendUrl',
    );

    return await this.sendMail({
      to: email,
      subject: `Bienvenue sur ${appName}`,
      text: `Bonjour ${userName || ''},\n\nBienvenue sur ${appName} ! Votre compte a été vérifié avec succès et vous pouvez maintenant vous connecter à notre plateforme.\n\n${frontendUrl}/auth/login\n\nCordialement,\nL'équipe ${appName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Bienvenue sur ${appName} !</h2>
          <p>Bonjour ${userName || ''},</p>
          <p>Votre compte a été vérifié avec succès et vous pouvez maintenant vous connecter à notre plateforme.</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${frontendUrl}/auth/login" style="background-color: #4CAF50; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Se connecter</a>
          </p>
          <p>Nous sommes ravis de vous compter parmi nos utilisateurs.</p>
          <p>Cordialement,<br>L'équipe ${appName}</p>
        </div>
      `,
    });
  }
}
