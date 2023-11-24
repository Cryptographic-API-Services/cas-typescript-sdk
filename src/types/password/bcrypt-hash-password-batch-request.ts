export class BcryptHashPasswordBatchRequest {
    public passwords: Array<string>;

    constructor(passwords: Array<string>) {
        this.passwords = passwords;
    }
}