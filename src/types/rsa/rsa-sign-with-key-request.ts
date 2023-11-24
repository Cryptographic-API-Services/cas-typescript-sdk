export class RsaSignWithKeyRequest {
    dataToSign: string;
    privateKey: string;

    constructor(dataToSign: string, privateKey: string) {
        this.dataToSign = dataToSign;
        this.privateKey = privateKey;
    }
}