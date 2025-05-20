import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class TwoFactorAuthDto {
    @ApiProperty({
        description: "Code d'authentification à deux facteurs",
        example: '123456',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le code 2FA est requis' })
    twoFactorCode: string;
}
