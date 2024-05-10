import { decryptCiphertextRsa, encryptPlaintextRsa, generateRsaKeys, RsaKeyPairResult, signRsa, verifyRsa } from "../../index";

export class RSAWrapper {

  public GetKeyPair(keySize: number): RsaKeyPairResult {
    if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
        throw new Error("You must provide an appropriate key size to generate RSA keys");
    }
    return generateRsaKeys(keySize);
  }

  public RsaEncryptBytes(publicKey: string, plaintext: Array<number>): Array<number> {
    if (!publicKey) {
      throw new Error("You must provide a public key to encrypt with RSA");
    }
    if (!plaintext || plaintext.length === 0) {
      throw new Error("You must provide an array of plaintext bytes to encrypt with RSA");
    }
    return encryptPlaintextRsa(publicKey, plaintext);
  }

  public RsaDecryptBytes(privateKey: string, ciphertext: Array<number>): Array<number> {
    if (!privateKey) {
      throw new Error("You must provide a private key to encrypt with RSA");
    }
    if (!ciphertext || ciphertext.length === 0) {
      throw new Error("You must provide an array of ciphertext bytes to encrypt with RSA");
    }
    return decryptCiphertextRsa(privateKey, ciphertext);
  }

  public RsaSignWithKeyBytes(privateKey: string, hash: Array<number>): Array<number> {
    if (!privateKey) {
      throw new Error("You must provide a private key to sign with RSA");
    }
    if (!hash || hash.length === 0) {
      throw new Error("You must provide an allocated hash to sign with RSA");
    }
    return signRsa(privateKey, hash);
  }

  public RsaVerifyBytes(publicKey: string, hash: Array<number>, signature: Array<number>): boolean {
    if (!publicKey) {
      throw new Error("You must provide a public key to verify with RSA");
    }
    if (!hash || hash.length === 0) {
      throw new Error("You must provide an allocated hash to verify with RSA");
    }
    if (!signature || signature.length === 0) {
      throw new Error("You must provide and allocated signature to verify with RSA");
    }
    return verifyRsa(publicKey, hash, signature);
  }
}
