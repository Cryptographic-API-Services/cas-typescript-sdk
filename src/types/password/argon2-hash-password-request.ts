export class Argon2HashPasswordRequest {
    passwordToHash: string;

    constructor(passwordToHash: string) {
        this.passwordToHash = passwordToHash;
    }
}