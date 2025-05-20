import { ApiPropertyOptional } from '@nestjs/swagger';
import {
    IsBoolean,
    IsEmail,
    IsEnum,
    IsOptional,
    IsString,
    Length,
    Matches,
} from 'class-validator';
import { UserRole } from 'generated/prisma';

export class UpdateUserDto {
    @ApiPropertyOptional({
        description: "Prénom de l'utilisateur",
        example: 'Jean',
    })
    @IsString()
    @IsOptional()
    @Length(1, 50, {
        message: 'Le prénom doit contenir entre 1 et 50 caractères',
    })
    firstName?: string;

    @ApiPropertyOptional({
        description: "Nom de l'utilisateur",
        example: 'Dupont',
    })
    @IsString()
    @IsOptional()
    @Length(1, 50, { message: 'Le nom doit contenir entre 1 et 50 caractères' })
    lastName?: string;

    @ApiPropertyOptional({
        description: "Adresse email de l'utilisateur",
        example: 'utilisateur@exemple.com',
    })
    @IsEmail({}, { message: "Format d'email invalide" })
    @IsOptional()
    email?: string;

    @ApiPropertyOptional({
        description: 'Nouveau mot de passe',
        example: 'NouveauMotDePasse123!',
        minLength: 8,
        maxLength: 100,
    })
    @IsString()
    @IsOptional()
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
    password?: string;

    @ApiPropertyOptional({
        description: "Rôle de l'utilisateur",
        enum: UserRole,
    })
    @IsEnum(UserRole, { message: 'Rôle invalide' })
    @IsOptional()
    role?: UserRole;

    @ApiPropertyOptional({
        description: "Statut actif de l'utilisateur",
    })
    @IsBoolean()
    @IsOptional()
    isActive?: boolean;
}
