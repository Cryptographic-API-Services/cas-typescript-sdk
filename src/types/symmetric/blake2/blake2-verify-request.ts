export class Blake2VerifyRequest {
    public hashSize: number;
    public dataToVerify: string;
    public hash: string;
    
    constructor(hashSize: number, dataToVerify: string, hash: string) {
        this.hashSize = hashSize;
        this.dataToVerify = dataToVerify;
        this.hash = hash;
    }
}