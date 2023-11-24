export class Blake2ED25519DalekSignResponse {
    public publicKey: string;
    public signature: string;

    constructor(publicKey: string, signature: string) {
        this.publicKey = publicKey;
        this.signature = signature;
    }
}