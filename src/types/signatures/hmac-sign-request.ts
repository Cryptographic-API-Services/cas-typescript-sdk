export class HmacSignRequest {
    key: string;
    message: string;

    constructor(key: string, message: string) {
        this.key = key;
        this.message = message;
    }
}