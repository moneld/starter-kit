export interface IPasswordService {
    changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string,
    ): Promise<void>;
    forgotPassword(email: string): Promise<void>;
    resetPassword(token: string, newPassword: string): Promise<void>;
    validatePasswordStrength(password: string): boolean;
}
