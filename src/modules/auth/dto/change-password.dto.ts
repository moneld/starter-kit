import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class ChangePasswordDto {
    @ApiProperty({
        description: 'Mot de passe actuel',
        example: 'MotDePasseActuel123!',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le mot de passe actuel est requis' })
    currentPassword: string;

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
    newPassword: string;

    @ApiProperty({
        description: 'Confirmation du nouveau mot de passe',
        example: 'NouveauMotDePasse123!',
    })
    @IsString()
    @IsNotEmpty({ message: 'La confirmation du mot de passe est requise' })
    newPasswordConfirm: string;
}
