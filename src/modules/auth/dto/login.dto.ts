import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
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
    })
    @IsString()
    @IsNotEmpty({ message: 'Le mot de passe est requis' })
    password: string;
}
