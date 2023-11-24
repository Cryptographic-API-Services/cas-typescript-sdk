export class Blake2RsaVerifyRequest {
    public blake2HashSize: number;
    public publicKey: string;
    public signature: string;
    public originalData: string;

    constructor(blake2HashSize: number, publicKey: string, signature: string, originalData: string) {
        this.blake2HashSize = blake2HashSize;
        this.publicKey = publicKey;
        this.signature = signature;
        this.originalData = originalData;
    }
}