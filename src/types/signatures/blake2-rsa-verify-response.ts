export class Blake2RsaVerifyResponse {
    public isValid: boolean;

    constructor(isValid: boolean) {
        this.isValid = isValid;
    }
}