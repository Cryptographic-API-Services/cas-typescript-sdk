export interface IPasswordHasherBase {
    hashPassword(password: string): string;
    verifyPassword(hashedPassword: string, passwordToVerify: string): boolean;
}