import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { INJECTION_TOKENS } from 'src/common/constants/injection-tokens';
import {
  IEmailProvider,
  IEmailService,
} from '../interfaces/email-provider.interface';

@Injectable()
export class EmailAdapter implements IEmailService {
  private readonly appName: string;
  private readonly frontendUrl: string;

  constructor(
    @Inject(INJECTION_TOKENS.EMAIL_PROVIDER)
    private readonly emailProvider: IEmailProvider,
    private readonly configService: ConfigService,
  ) {
    this.appName = this.configService.get<string>(
      'app.general.name',
      'Application',
    );
    this.frontendUrl = this.configService.get<string>(
      'app.general.frontendUrl',
      '',
    );
  }

  async sendVerificationEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean> {
    const verificationUrl = `${this.frontendUrl}/auth/verify-email?token=${token}`;

    return this.emailProvider.sendMail({
      to: email,
      subject: `Email Verification - ${this.appName}`,
      template: 'verification',
      context: {
        userName,
        verificationUrl,
        appName: this.appName,
      },
    });
  }

  async sendPasswordResetEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean> {
    const resetUrl = `${this.frontendUrl}/auth/reset-password?token=${token}`;

    return this.emailProvider.sendMail({
      to: email,
      subject: `Password Reset - ${this.appName}`,
      template: 'password-reset',
      context: {
        userName,
        resetUrl,
        appName: this.appName,
      },
    });
  }

  async sendWelcomeEmail(email: string, userName?: string): Promise<boolean> {
    return this.emailProvider.sendMail({
      to: email,
      subject: `Welcome to ${this.appName}`,
      template: 'welcome',
      context: {
        userName,
        appName: this.appName,
        loginUrl: `${this.frontendUrl}/auth/login`,
      },
    });
  }

  async sendSecurityAlert(email: string, alert: any): Promise<boolean> {
    return this.emailProvider.sendMail({
      to: email,
      subject: `Security Alert - ${this.appName}`,
      template: 'security-alert',
      context: {
        alert,
        appName: this.appName,
      },
    });
  }
}
