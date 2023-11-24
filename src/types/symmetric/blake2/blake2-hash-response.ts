export class Blake2HashResponse {
    public hashedData: string
    
    constructor(hashedData: string) {
        this.hashedData = hashedData;
    }
}