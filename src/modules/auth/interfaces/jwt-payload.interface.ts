export interface JwtPayload {
    sub: string; // ID de l'utilisateur
    email: string; // Email de l'utilisateur
    role: string; // Rôle de l'utilisateur
    isActive: boolean; // Statut actif de l'utilisateur
    isTwoFactorAuth?: boolean; // Indique si l'authentification à deux facteurs est complétée
    iat?: number; // Issued at (quand le token a été émis)
    exp?: number; // Expiration time
}
