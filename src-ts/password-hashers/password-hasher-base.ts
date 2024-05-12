export interface IPasswordHasherBase {
    hashPassword(password: string): string;
    verify(hashedPassword: string, passwordToVerify: string): boolean;
    hashPasswordThreadPool(password: string): string;
    verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean;
}