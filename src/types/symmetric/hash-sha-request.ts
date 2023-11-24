export class HashShaRequest {
    public dataToEncrypt: string;

    constructor(dataToEncrypt: string) {
        this.dataToEncrypt = dataToEncrypt;
    }
}