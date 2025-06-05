import { Injectable } from '@nestjs/common';
import {
    ISecurityAnalyzer,
    SecurityAlert,
    SecurityContext,
} from '../interfaces/security-analyzer.interface';

@Injectable()
export class SecurityAnalyzerRegistry {
    private analyzers: ISecurityAnalyzer[] = [];

    register(analyzer: ISecurityAnalyzer): void {
        this.analyzers.push(analyzer);
        // Sort by priority (lower number = higher priority)
        this.analyzers.sort((a, b) => a.getPriority() - b.getPriority());
    }

    async analyzeAll(context: SecurityContext): Promise<SecurityAlert[]> {
        const allAlerts: SecurityAlert[] = [];

        for (const analyzer of this.analyzers) {
            try {
                const alerts = await analyzer.analyze(context);
                allAlerts.push(...alerts);
            } catch (error) {
                // Log error but continue with other analyzers
                console.error(
                    `Error in ${analyzer.getName()}: ${error.message}`,
                );
            }
        }

        return allAlerts;
    }

    getAnalyzers(): ISecurityAnalyzer[] {
        return [...this.analyzers];
    }
}
