export interface IEmailProvider {
  sendMail(options: {
    to: string;
    subject: string;
    text?: string;
    html?: string;
    template?: string;
    context?: any;
  }): Promise<boolean>;
}

export interface IEmailService {
  sendVerificationEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean>;
  sendPasswordResetEmail(
    email: string,
    token: string,
    userName?: string,
  ): Promise<boolean>;
  sendWelcomeEmail(email: string, userName?: string): Promise<boolean>;
  sendSecurityAlert(email: string, alert: any): Promise<boolean>;
}
