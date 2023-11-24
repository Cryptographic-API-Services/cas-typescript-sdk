export class ScryptHashPasswordRequest {
    passwordToHash: string;

    constructor(passwordToHash: string) {
        this.passwordToHash = passwordToHash;
    }
}