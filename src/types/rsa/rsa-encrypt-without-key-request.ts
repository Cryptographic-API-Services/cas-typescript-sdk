export class RsaEncryptWithoutKeyRequest {
    dataToEncrypt: string;
    keySize: number;

    constructor(dataToEncrypt: string, keySize: number) {
        this.dataToEncrypt = dataToEncrypt;
        this.keySize = keySize;
    }
}