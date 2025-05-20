import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class ResetPasswordDto {
    @ApiProperty({
        description: 'Token de réinitialisation du mot de passe',
        example: '550e8400-e29b-41d4-a716-446655440000',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le token est requis' })
    token: string;

    @ApiProperty({
        description: 'Nouveau mot de passe',
        example: 'NouveauMotDePasse123!',
        minLength: 8,
        maxLength: 100,
    })
    @IsString()
    @IsNotEmpty({ message: 'Le nouveau mot de passe est requis' })
    @Length(8, 100, {
        message: 'Le mot de passe doit contenir entre 8 et 100 caractères',
    })
    @Matches(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        {
            message:
                'Le mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial',
        },
    )
    password: string;

    @ApiProperty({
        description: 'Confirmation du nouveau mot de passe',
        example: 'NouveauMotDePasse123!',
    })
    @IsString()
    @IsNotEmpty({ message: 'La confirmation du mot de passe est requise' })
    passwordConfirm: string;
}
