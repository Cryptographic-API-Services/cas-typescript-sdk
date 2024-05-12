import {
  ascon128Decrypt,
  ascon128Encrypt,
  ascon128KeyGenerate,
  ascon128NonceGenerate,
} from "../../index";

export class AsconWrapper {
  ascon128Key(): Array<number> {
    return ascon128KeyGenerate();
  }

  ascon128Nonce(): Array<number> {
    return ascon128NonceGenerate();
  }

  ascon128Encrypt(
    key: Array<number>,
    nonce: Array<number>,
    plaintext: Array<number>,
  ): Array<number> {
    if (!key || key.length === 0) {
      throw new Error("Key is required");
    }
    if (!nonce || nonce.length === 0) {
      throw new Error("Nonce is required");
    }
    if (!plaintext || plaintext.length === 0) {
      throw new Error("Plaintext is required");
    }
    return ascon128Encrypt(key, nonce, plaintext);
  }

  ascon128Decrypt(
    key: Array<number>,
    nonce: Array<number>,
    ciphertext: Array<number>,
  ): Array<number> {
    if (!key || key.length === 0) {
      throw new Error("Key is required");
    }
    if (!nonce || nonce.length === 0) {
      throw new Error("Nonce is required");
    }
    if (!ciphertext || ciphertext.length === 0) {
      throw new Error("Ciphertext is required");
    }
    return ascon128Decrypt(key, nonce, ciphertext);
  }
}
