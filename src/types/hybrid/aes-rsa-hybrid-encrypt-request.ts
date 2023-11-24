export class AesRsaHybridEncryptRequest {
    public nonce: string;
    public keySize: number;
    public dataToEncrypt: string;
    public aesType: number;
    
    constructor(nonceKey: string, keySize: number, dataToEncrypt: string, aesType: number) {
        this.nonce = nonceKey;
        this.keySize = keySize;
        this.dataToEncrypt = dataToEncrypt;
        this.aesType = aesType;
    }
}