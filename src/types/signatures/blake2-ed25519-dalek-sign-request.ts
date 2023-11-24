export class Blake2ED25519DalekSignRequest {
    public hashSize: number;
    public dataToSign: string;

    constructor(hashSize: number, dataToSign: string) {
        this.hashSize = hashSize;
        this.dataToSign = dataToSign;
    }
}