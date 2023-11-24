export class Blake2HashRequest {
    public hashSize: number;
    public dataToHash: string;
    
    constructor(hashSize: number, dataToHash: string) {
        this.hashSize = hashSize;
        this.dataToHash = dataToHash;
    }
}