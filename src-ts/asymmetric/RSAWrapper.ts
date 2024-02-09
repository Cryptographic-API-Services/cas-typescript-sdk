import { decryptCiphertextRsa, encryptPlaintextRsa, generateRsaKeys, RsaKeyPairResult } from "../../index";

export class RSAWrapper {
  public generateKeys(keySize: number): RsaKeyPairResult {
    if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
        throw new Error("You must provide an appropriate key size to generate RSA keys");
    }
    return generateRsaKeys(keySize);
  }

  public encrypt(publicKey: string, plaintext: Array<number>): Array<number> {
    if (!publicKey) {
      throw new Error("You must provide a public key to encrypt with RSA");
    }
    if (!plaintext || plaintext.length === 0) {
      throw new Error("You must provide an array of plaintext bytes to encrypt with RSA");
    }
    return encryptPlaintextRsa(publicKey, plaintext);
  }

  public decrypt(privateKey: string, ciphertext: Array<number>): Array<number> {
    if (!privateKey) {
      throw new Error("You must provide a private key to encrypt with RSA");
    }
    if (!ciphertext || ciphertext.length === 0) {
      throw new Error("You must provide an array of ciphertext bytes to encrypt with RSA");
    }
    return decryptCiphertextRsa(privateKey, ciphertext);
  }
}
