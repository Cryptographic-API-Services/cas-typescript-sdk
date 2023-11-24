export class BCryptHashPasswordRequest {
    password: string;

    constructor(password: string) {
        this.password = password;
    }
}