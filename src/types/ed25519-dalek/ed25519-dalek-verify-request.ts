export class ED25519DalekVerifyRequest {
    publicKey: string;
    signature: string;
    dataToVerify: string;

    constructor(publicKey: string, signature: string, dataToVerify: string) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.dataToVerify = dataToVerify;
    }
}