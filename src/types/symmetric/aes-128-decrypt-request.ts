export class Aes128DecryptRequest {
    dataToDecrypt: string;
    nonceKey: string;
    key: string;
    aesType: number;

    constructor(dataToDecrypt: string, nonceKey: string, key: string, aesType: number) {
        this.dataToDecrypt = dataToDecrypt;
        this.nonceKey = nonceKey;
        this.key = key;
        this.aesType = aesType;
    }
}