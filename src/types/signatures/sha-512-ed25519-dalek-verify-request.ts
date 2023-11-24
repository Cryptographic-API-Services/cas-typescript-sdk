export class SHA512ED25519DalekVerifyRequest {
    signature: string;
    dataToVerify: string;
    publicKey: string;

    constructor(signature: string, dataToVerify: string, publicKey: string) {
        this.signature = signature;
        this.dataToVerify = dataToVerify;
        this.publicKey = publicKey;
    }
}