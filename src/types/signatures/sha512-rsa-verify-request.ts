export class SHA512RsaVerfiyRequest {
    publicKey: string;
    originalData: string;
    signature: string;

    constructor(publicKey: string, originalData: string, signature: string) {
        this.publicKey = publicKey;
        this.originalData = originalData;
        this.signature = signature;
    }
}