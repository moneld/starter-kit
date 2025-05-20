import { ApiProperty } from '@nestjs/swagger';
import {
    IsEmail,
    IsNotEmpty,
    IsString,
    Length,
    Matches,
} from 'class-validator';

export class RegisterDto {
    @ApiProperty({
        description: "L'adresse email de l'utilisateur",
        example: 'utilisateur@exemple.com',
    })
    @IsEmail({}, { message: "Format d'email invalide" })
    @IsNotEmpty({ message: "L'email est requis" })
    email: string;

    @ApiProperty({
        description: "Mot de passe de l'utilisateur",
        example: 'MotDePasse123!',
        minLength: 8,
        maxLength: 100,
    })
    @IsString()
    @IsNotEmpty({ message: 'Le mot de passe est requis' })
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
        description: 'Confirmation du mot de passe',
        example: 'MotDePasse123!',
    })
    @IsString()
    @IsNotEmpty({ message: 'La confirmation du mot de passe est requise' })
    passwordConfirm: string;

    @ApiProperty({
        description: "Prénom de l'utilisateur",
        example: 'Jean',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le prénom est requis' })
    @Length(1, 50, {
        message: 'Le prénom doit contenir entre 1 et 50 caractères',
    })
    firstName: string;

    @ApiProperty({
        description: "Nom de l'utilisateur",
        example: 'Dupont',
    })
    @IsString()
    @IsNotEmpty({ message: 'Le nom est requis' })
    @Length(1, 50, { message: 'Le nom doit contenir entre 1 et 50 caractères' })
    lastName: string;
}
