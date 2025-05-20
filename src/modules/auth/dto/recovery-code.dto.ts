import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class RecoveryCodeDto {
    @ApiProperty({
        description: "Code de récupération d'urgence",
        example: 'ABCD-1234-EFGH-5678',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le code de récupération est requis' })
    recoveryCode: string;
}
