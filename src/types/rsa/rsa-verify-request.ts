export class RsaVerifyRequest {
    signature: string;
    publicKey: string;
    originalData: string;

    constructor(signature: string, publicKey: string, originalData: string) {
        this.signature = signature;
        this.publicKey = publicKey;
        this.originalData = originalData;
    }   
}