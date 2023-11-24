export class MD5VerifyRequest {
    hashToVerify: string;
    toHash: string;

    constructor(hashToVerify: string, toHash: string) {
        this.hashToVerify = hashToVerify;
        this.toHash = toHash;
    }
}