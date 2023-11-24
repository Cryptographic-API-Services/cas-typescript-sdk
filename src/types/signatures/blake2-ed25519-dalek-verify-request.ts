export class Blake2ED25519DalekVerifyRequest {
    public hashSize: number;
    public publicKey: string;
    public dataToVerify: string;
    public signature: string;

    constructor(hashSize: number, publicKey: string, dataToVerify: string, signature: string) {
        this.hashSize = hashSize;
        this.publicKey = publicKey;
        this.dataToVerify = dataToVerify;
        this.signature = signature;
    }
}