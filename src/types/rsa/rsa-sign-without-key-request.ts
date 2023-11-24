export class RsaSignWithoutKeyRequest {
    dataToSign: string;
    keySize: number;

    constructor(dataToSign: string, keySize: number) {
        this.dataToSign = dataToSign;
        this.keySize = keySize;
    }
}