export class MD5HashRequest {
    dataToHash: string; 

    constructor(dataToHash: string) {
        this.dataToHash = dataToHash;
    }
}