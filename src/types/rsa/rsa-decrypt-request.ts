export class RsaDecryptRequest {
    privateKey: string;
    dataToDecrypt: string;

    constructor(privateKey: string, dataToDecrypt: string) {
        this.privateKey = privateKey;
        this.dataToDecrypt = dataToDecrypt;
    }
}