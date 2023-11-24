export class Aes128EncryptRequest {
    dataToEncrypt: string;
    nonceKey: string;
    aesType: number;

    constructor(dataToEncrypt: string, nonce: string, aesType: number) {
        this.dataToEncrypt = dataToEncrypt;
        this.nonceKey = nonce;
        this.aesType = aesType;
    }
}