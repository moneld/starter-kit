import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MailModule } from 'src/modules/mail/mail.module';
import { PrismaModule } from 'src/modules/prisma/prisma.module';
import { INJECTION_TOKENS } from '../constants/injection-tokens';
import { DeviceAnalyzer } from '../security/analyzers/device-analyzer';
import { LocationAnalyzer } from '../security/analyzers/location-analyzer';
import { SessionAnalyzer } from '../security/analyzers/session-analyzer';
import { SecurityAnalyzerRegistry } from '../security/security-analyzer.registry';
import { AnomalyDetectionService } from '../services/anomaly-detection.service';
import { CryptoService } from '../services/crypto.service';
import { EncryptionAdapter } from '../services/encryption-adapter.service';
import { HashingService } from '../services/hashing.service';
import { KeyRotationService } from '../services/key-rotation.service';

const securityProviders = [
    CryptoService,
    KeyRotationService,
    AnomalyDetectionService,
    SecurityAnalyzerRegistry,
    LocationAnalyzer,
    SessionAnalyzer,
    DeviceAnalyzer,
    {
        provide: INJECTION_TOKENS.ENCRYPTION_SERVICE,
        useClass: EncryptionAdapter,
    },
    {
        provide: INJECTION_TOKENS.HASHING_SERVICE,
        useClass: HashingService,
    },
];

@Global()
@Module({
    imports: [ConfigModule, PrismaModule, MailModule],
    providers: securityProviders,
    exports: [
        INJECTION_TOKENS.ENCRYPTION_SERVICE,
        INJECTION_TOKENS.HASHING_SERVICE,
        AnomalyDetectionService,
        SecurityAnalyzerRegistry,
        CryptoService,
    ],
})
export class SecurityModule {
    constructor(
        private readonly registry: SecurityAnalyzerRegistry,
        private readonly locationAnalyzer: LocationAnalyzer,
        private readonly sessionAnalyzer: SessionAnalyzer,
        private readonly deviceAnalyzer: DeviceAnalyzer,
    ) {
        // Register all analyzers
        this.registry.register(this.locationAnalyzer);
        this.registry.register(this.sessionAnalyzer);
        this.registry.register(this.deviceAnalyzer);
    }
}
