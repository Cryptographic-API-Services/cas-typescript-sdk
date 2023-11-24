export class HmacVerifyRequest {
    key: string;
    message: string;
    signature: string;

    constructor(key: string, message: string, signature: string) {
        this.key = key;
        this.message = message;
        this.signature = signature;
    }
}