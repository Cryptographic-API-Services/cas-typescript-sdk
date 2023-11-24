export class Blake2VerifyResponse {
    public isValid: boolean
    
    constructor(isValid: boolean) {
        this.isValid = isValid;
    }
}