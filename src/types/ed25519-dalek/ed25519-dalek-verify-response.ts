export class ED25519DalekVerifyResponse {
    isValid: boolean;

    constructor(isValid: boolean) {
        this.isValid = isValid;
    }
}