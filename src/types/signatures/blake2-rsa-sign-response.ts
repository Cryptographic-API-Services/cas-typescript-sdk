export class Blake2RsaSignResponse {
    public signature: string;
    public privateKey: string;
    public publicKey: string;

    constructor(signature: string, privateKey: string, publicKey: string) {
        this.signature = signature;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}