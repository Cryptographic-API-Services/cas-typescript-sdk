import { RsaKeyPairResult } from "../../..";
import { RSAWrapper } from "../../asymmetric";
import { AESWrapper } from "../../symmetric";

export class AESRSAHybridInitializer {
    public aesType: number;
    public aesKey: Array<number>;
    public aesNonce: Array<number>;
    public rsaKeyPair: RsaKeyPairResult;

    constructor(aesType: number, rsaSize: number) {
        if (aesType !== 128 && aesType !== 256) {
            throw new Error("Need an appropriate AES size to generate a hybrid initalizer");
        }
        this.aesType = aesType;
        let aesWrapper = new AESWrapper();
        this.aesKey = (aesType === 128) ? aesWrapper.aes128Key() : aesWrapper.aes256Key();
        this.aesNonce = aesWrapper.aesNonce();
        if (rsaSize !== 1028 && rsaSize !== 2048 && rsaSize !== 4096) {
            throw new Error("You must provide an appropriate RSA Key pair size to generate a hybrid initalizer");
        }
        this.rsaKeyPair = new RSAWrapper().generateKeys(rsaSize); 
    }
}