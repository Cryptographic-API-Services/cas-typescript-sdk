export class ScryptHashPasswordBatchResponse {
    public hashedPasswords: Array<string>;

    constructor(hashedPasswords: Array<string>) {
        this.hashedPasswords = hashedPasswords;
    }
}