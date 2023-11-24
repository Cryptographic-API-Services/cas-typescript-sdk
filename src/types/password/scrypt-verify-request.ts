export class ScryptVerifyRequest {
    public password: string;
    public hashedPassword: string;

    constructor(password: string, hashedPassword: string) {
        this.password = password;
        this.hashedPassword = hashedPassword;
    }
}