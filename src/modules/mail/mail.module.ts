import { Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../common/constants/injection-tokens';
import { EmailAdapter } from './adapters/email.adapter';
import { MailService } from './mail.service';

const mailProviders = [
    {
        provide: INJECTION_TOKENS.EMAIL_PROVIDER,
        useClass: MailService,
    },
    {
        provide: INJECTION_TOKENS.EMAIL_SERVICE,
        useClass: EmailAdapter,
    },
];

@Module({
    providers: mailProviders,
    exports: [INJECTION_TOKENS.EMAIL_SERVICE, INJECTION_TOKENS.EMAIL_PROVIDER],
})
export class MailModule {}
