export class RsaDecryptWithoutPrivateKeyRequest {
    publicKey: string;
    dataToDecrypt: string;

    constructor(publicKey: string, dataToDecrypt: string) {
        this.publicKey = publicKey;
        this.dataToDecrypt = dataToDecrypt;
    }
}