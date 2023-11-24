export class Aes256EncryptRequest {
    dataToEncrypt: string;
    nonceKey: string;
    aesType: number;

    constructor(dataToEncrypt: string, nonceKey: string, aesType: number) {
        this.dataToEncrypt = dataToEncrypt;
        this.nonceKey = nonceKey;
        this.aesType = aesType;
    }
}