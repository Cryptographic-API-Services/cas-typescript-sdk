export class BCryptVerifyRequest {
    password: string;
    hashedPassword: string;

    constructor(password: string, hashedPassword: string) {
        this.password = password;
        this.hashedPassword = hashedPassword;
    }
}