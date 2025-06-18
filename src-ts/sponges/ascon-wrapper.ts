import {
  ascon128Decrypt,
  ascon128Encrypt,
  ascon128KeyGenerate,
  ascon128NonceGenerate,
} from "../../index.d";

export class AsconWrapper {
  /**
   * Generates an Ascon 128 key
   * @returns Array<number>
   */
  ascon128Key(): Array<number> {
    return ascon128KeyGenerate();
  }

  /**
   * Generates and Ascon 128 nonce.
   * @returns Array<number>
   */
  ascon128Nonce(): Array<number> {
    return ascon128NonceGenerate();
  }

  /**
   * Encrypts with Ascon 128 using the key and nonce generated from ascon128Key() and ascon128Nonce() respectively.
   * @param key 
   * @param nonce 
   * @param plaintext 
   * @returns 
   */
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

   /**
   * Decrypts with Ascon 128 using the key and nonce generated from ascon128Key() and ascon128Nonce() respectively.
   * @param key 
   * @param nonce 
   * @param ciphertext 
   * @returns Array<number>
   */
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
