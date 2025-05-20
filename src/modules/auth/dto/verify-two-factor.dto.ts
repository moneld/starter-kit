import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyTwoFactorDto {
    @ApiProperty({
        description: "Secret de l'authentification à deux facteurs",
        example: 'ABCDEFGHIJKLMNOP',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le secret 2FA est requis' })
    secret: string;

    @ApiProperty({
        description:
            "Code à six chiffres généré par l'application d'authentification",
        example: '123456',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le code de vérification est requis' })
    code: string;
}
