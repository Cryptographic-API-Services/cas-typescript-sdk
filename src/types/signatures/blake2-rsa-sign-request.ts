export class Blake2RsaSignRequest {
    public blake2HashSize: number;
    public rsaKeySize: number;
    public dataToSign: string;

    constructor(blake2HashSize: number, rsaKeySize: number, dataToSign: string) {
        this.blake2HashSize = blake2HashSize;
        this.rsaKeySize = rsaKeySize;
        this.dataToSign = dataToSign;
    }
}