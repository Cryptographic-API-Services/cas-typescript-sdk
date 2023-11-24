export class SHA512RsaSignRequest {
    dataToHash: string;
    keySize: number;

    constructor(dataToHash: string, keySize: number) {
        this.dataToHash = dataToHash;
        this.keySize = keySize;
    }
}