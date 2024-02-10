export class AesRsaHybridEncryptResult {
    ciphertext: Array<number>;
    encryptedAesKey: Array<number>;
    aesType: number;
    aesNonce: Array<number>;

    constructor(cipherText: Array<number>, encryptAesKey: Array<number>, aesType: number, aesNonce: Array<number>) {
        this.ciphertext = cipherText;
        this.encryptedAesKey = encryptAesKey;
        this.aesType = aesType;
        this.aesNonce = aesNonce;
    }
}