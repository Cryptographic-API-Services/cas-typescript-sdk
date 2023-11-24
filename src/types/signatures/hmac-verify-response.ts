export class HmacVerifyResponse {
    isValid: boolean;
    
    constructor(isValid: boolean) {
        this.isValid = isValid;
    }
}