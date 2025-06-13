import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs/promises';
import * as handlebars from 'handlebars';
import * as path from 'path';
const mjml = require('mjml');

export interface TemplateContext {
    [key: string]: any;
}

@Injectable()
export class TemplateService implements OnModuleInit {
    private readonly logger = new Logger(TemplateService.name);
    private readonly templatesPath: string;
    private readonly mjmlPath: string;
    private readonly compiledPath: string;
    private compiledTemplates: Map<string, HandlebarsTemplateDelegate> =
        new Map();

    constructor(private readonly configService: ConfigService) {
        this.templatesPath = path.join(
            process.cwd(),
            'src',
            'modules',
            'mail',
            'templates',
        );
        this.mjmlPath = path.join(this.templatesPath, 'mjml');
        this.compiledPath = path.join(this.templatesPath, 'compiled');
    }

    async onModuleInit() {
        await this.ensureDirectoriesExist();
        await this.compileTemplates();
        await this.loadCompiledTemplates();
        this.registerHelpers();
    }

    /**
     * Compile les templates MJML en Handlebars
     */
    private async compileTemplates(): Promise<void> {
        try {
            const mjmlFiles = await fs.readdir(this.mjmlPath);
            const mjmlTemplates = mjmlFiles.filter(
                (file) => file.endsWith('.mjml') && file !== 'base.mjml',
            );

            for (const templateFile of mjmlTemplates) {
                const templateName = path.basename(templateFile, '.mjml');
                await this.compileMjmlTemplate(templateName);
            }

            this.logger.log(
                `${mjmlTemplates.length} templates MJML compilés avec succès`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors de la compilation des templates: ${error.message}`,
            );
        }
    }

    /**
     * Compile un template MJML spécifique
     */
    private async compileMjmlTemplate(templateName: string): Promise<void> {
        try {
            const mjmlFilePath = path.join(
                this.mjmlPath,
                `${templateName}.mjml`,
            );
            const mjmlContent = await fs.readFile(mjmlFilePath, 'utf-8');

            // Compiler MJML en HTML
            const mjmlResult = mjml(mjmlContent, {
                validationLevel: 'soft',
                fonts: {
                    Inter: 'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap',
                },
            });

            if (mjmlResult.errors.length > 0) {
                this.logger.warn(
                    `Avertissements MJML pour ${templateName}:`,
                    mjmlResult.errors,
                );
            }

            // Sauvegarder le HTML compilé comme template Handlebars
            const compiledFilePath = path.join(
                this.compiledPath,
                `${templateName}.hbs`,
            );
            await fs.writeFile(compiledFilePath, mjmlResult.html, 'utf-8');

            this.logger.debug(`Template ${templateName} compilé avec succès`);
        } catch (error) {
            this.logger.error(
                `Erreur compilation template ${templateName}: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Charge tous les templates compilés en mémoire
     */
    private async loadCompiledTemplates(): Promise<void> {
        try {
            const compiledFiles = await fs.readdir(this.compiledPath);
            const hbsFiles = compiledFiles.filter((file) =>
                file.endsWith('.hbs'),
            );

            for (const templateFile of hbsFiles) {
                const templateName = path.basename(templateFile, '.hbs');
                const templatePath = path.join(this.compiledPath, templateFile);
                const templateContent = await fs.readFile(
                    templatePath,
                    'utf-8',
                );

                const compiledTemplate = handlebars.compile(templateContent);
                this.compiledTemplates.set(templateName, compiledTemplate);
            }

            this.logger.log(
                `${hbsFiles.length} templates Handlebars chargés en mémoire`,
            );
        } catch (error) {
            this.logger.error(
                `Erreur lors du chargement des templates: ${error.message}`,
            );
        }
    }

    /**
     * Enregistre les helpers Handlebars personnalisés
     */
    private registerHelpers(): void {
        // Helper pour formater les dates
        handlebars.registerHelper(
            'formatDate',
            (date: Date, format: string = 'DD/MM/YYYY') => {
                if (!date) return '';
                return new Date(date).toLocaleDateString('fr-FR');
            },
        );

        // Helper pour les URLs absolues
        handlebars.registerHelper('absoluteUrl', (path: string) => {
            const baseUrl = this.configService.get<string>(
                'app.general.frontendUrl',
                '',
            );
            return `${baseUrl}${path.startsWith('/') ? path : '/' + path}`;
        });

        // Helper conditionnel
        handlebars.registerHelper('if_eq', function (a, b, options) {
            if (a === b) {
                return options.fn(this);
            }
            return options.inverse(this);
        });

        // Helper pour capitaliser
        handlebars.registerHelper('capitalize', (str: string) => {
            if (!str) return '';
            return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
        });

        this.logger.debug('Helpers Handlebars enregistrés');
    }

    /**
     * Génère le HTML d'un email à partir d'un template
     */
    async renderTemplate(
        templateName: string,
        context: TemplateContext,
    ): Promise<string> {
        const template = this.compiledTemplates.get(templateName);

        if (!template) {
            throw new Error(`Template '${templateName}' non trouvé`);
        }

        try {
            // Ajouter les variables globales au contexte
            const globalContext = {
                ...context,
                appName: this.configService.get<string>(
                    'app.general.name',
                    'Application',
                ),
                frontendUrl: this.configService.get<string>(
                    'app.general.frontendUrl',
                    '',
                ),
                currentYear: new Date().getFullYear(),
                supportEmail: this.configService.get<string>(
                    'app.mail.from',
                    'support@example.com',
                ),
            };

            return template(globalContext);
        } catch (error) {
            this.logger.error(
                `Erreur rendu template ${templateName}: ${error.message}`,
            );
            throw error;
        }
    }

    /**
     * Recompile et recharge un template spécifique (utile en développement)
     */
    async recompileTemplate(templateName: string): Promise<void> {
        await this.compileMjmlTemplate(templateName);

        const templatePath = path.join(
            this.compiledPath,
            `${templateName}.hbs`,
        );
        const templateContent = await fs.readFile(templatePath, 'utf-8');
        const compiledTemplate = handlebars.compile(templateContent);

        this.compiledTemplates.set(templateName, compiledTemplate);
        this.logger.log(`Template ${templateName} recompilé et rechargé`);
    }

    /**
     * Assure que les dossiers nécessaires existent
     */
    private async ensureDirectoriesExist(): Promise<void> {
        const directories = [
            this.templatesPath,
            this.mjmlPath,
            this.compiledPath,
        ];

        for (const dir of directories) {
            try {
                await fs.access(dir);
            } catch {
                await fs.mkdir(dir, { recursive: true });
                this.logger.log(`Dossier créé: ${dir}`);
            }
        }
    }

    /**
     * Liste tous les templates disponibles
     */
    getAvailableTemplates(): string[] {
        return Array.from(this.compiledTemplates.keys());
    }
}
