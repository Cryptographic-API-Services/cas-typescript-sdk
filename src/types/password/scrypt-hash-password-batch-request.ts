export class ScryptHashPasswordBatchRequest {
    public passwords: Array<string>;

    constructor(passwords: Array<string>) {
        this.passwords = passwords;
    }
}