export abstract class PasswordHasherBase implements IPasswordHasherBase {
    abstract hashPassword(password: string): string;
    abstract verifyPassword(hashedPassword: string, passwordToVerify: string): boolean;
}


export interface IPasswordHasherBase {
    hashPassword(password: string): string;
    verifyPassword(hashedPassword: string, passwordToVerify: string): boolean;
}