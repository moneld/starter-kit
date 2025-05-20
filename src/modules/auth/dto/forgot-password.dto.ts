import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
    @ApiProperty({
        description: "L'adresse email de l'utilisateur",
        example: 'utilisateur@exemple.com',
    })
    @IsEmail({}, { message: "Format d'email invalide" })
    @IsNotEmpty({ message: "L'email est requis" })
    email: string;
}
