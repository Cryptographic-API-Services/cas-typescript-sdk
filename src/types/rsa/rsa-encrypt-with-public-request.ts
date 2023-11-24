export class RsaEncryptWithPublicRequest {
    publicKey: string;
    dataToEncrypt: string;

    constructor(publicKey: string, dataToEncrypt: string) {
        this.publicKey = publicKey;
        this.dataToEncrypt = dataToEncrypt;
    }
}