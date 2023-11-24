export class AesRsaHybridDecryptRequest {
    privateRsaKey: string;
    encryptedAesKey: string;
    nonce: string;
    encryptedData: string;
    aesType: number;

    constructor(privateRsaKey: string, encryptedAesKey: string, nonce: string, encryptedData: string, aesType: number) {
        this.privateRsaKey = privateRsaKey;
        this.encryptedAesKey = encryptedAesKey;
        this.nonce = nonce;
        this.encryptedData = encryptedData;
        this.aesType = aesType;
    }
}