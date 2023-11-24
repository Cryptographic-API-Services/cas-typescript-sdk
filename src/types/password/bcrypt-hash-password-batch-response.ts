export class BcryptEncryptBatchResponse {
    public hashedPasswords: Array<string>;

    constructor(hashedPasswords: Array<string>) {
        this.hashedPasswords = hashedPasswords;
    }
}