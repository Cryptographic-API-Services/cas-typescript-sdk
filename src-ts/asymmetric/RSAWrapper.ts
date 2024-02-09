import { generateRsaKeys, RsaKeyPairResult } from "../../index";

export class RSAWrapper {
  public generateKeys(keySize: number): RsaKeyPairResult {
    if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
        throw new Error("You must provide an appropriate key size to generate RSA keys");
    }
    return generateRsaKeys(keySize);
  }
}
