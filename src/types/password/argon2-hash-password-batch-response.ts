export class Argon2HashPasswordBatchResponse {
    public hashedPasswords: Array<string>;

    constructor(hashedPasswords: Array<string>) {
        this.hashedPasswords = hashedPasswords;
    }
}