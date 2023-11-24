export class Argon2HashPasswordBatchRequest {
    public passwords: Array<string>;

    constructor(passwords: Array<string>) {
        this.passwords = passwords;
    }
}