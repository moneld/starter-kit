import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { IEmailProvider } from './interfaces/email-provider.interface';
import { TemplateContext, TemplateService } from './services/template.service';

@Injectable()
export class MailService implements IEmailProvider {
    private readonly logger = new Logger(MailService.name);
    private transporter: nodemailer.Transporter;

    constructor(
        private readonly configService: ConfigService,
        private readonly templateService: TemplateService,
    ) {
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

        if (
            this.configService.get<string>('app.general.nodeEnv') ===
            'development'
        ) {
            this.verifyConnection();
        }
    }

    private async verifyConnection() {
        try {
            await this.transporter.verify();
            this.logger.log('Connexion SMTP vérifiée avec succès');
        } catch (error) {
            this.logger.error(`Erreur de connexion SMTP: ${error.message}`);
        }
    }

    async sendMail(options: {
        to: string;
        subject: string;
        template?: string;
        context?: TemplateContext;
        text?: string;
        html?: string;
    }): Promise<boolean> {
        try {
            const { to, subject, template, context, text, html } = options;

            let htmlContent = html;
            let textContent = text;

            // Si un template est spécifié, le compiler avec MJML + Handlebars
            if (template && context) {
                htmlContent = await this.templateService.renderTemplate(
                    template,
                    context,
                );

                // Générer une version texte basique si elle n'existe pas
                if (!textContent) {
                    textContent = this.generateTextFromHtml(htmlContent);
                }
            }

            await this.transporter.sendMail({
                from: this.configService.get<string>('app.mail.from'),
                to,
                subject,
                text: textContent || '',
                html: htmlContent || '',
            });

            this.logger.log(`Email envoyé à ${to}: ${subject}`);
            return true;
        } catch (error) {
            this.logger.error(`Erreur d'envoi d'email: ${error.message}`);
            return false;
        }
    }

    /**
     * Génère une version texte basique à partir du HTML
     */
    private generateTextFromHtml(html: string): string {
        return html
            .replace(/<style[^>]*>.*?<\/style>/gs, '') // Supprimer CSS
            .replace(/<script[^>]*>.*?<\/script>/gs, '') // Supprimer JavaScript
            .replace(/<[^>]*>/g, '') // Supprimer toutes les balises HTML
            .replace(/\s+/g, ' ') // Normaliser les espaces
            .trim();
    }
}
