import {
  ascon128Decrypt,
  ascon128Encrypt,
  ascon128KeyGenerate,
  ascon128NonceGenerate,
} from "../../index";


export class AsconWrapper {
  /**
   * Generates an Ascon 128 key
   * @returns Uint8Array
   */
  
  ascon128Key(): Uint8Array {
    return ascon128KeyGenerate();
  }

  /**
   * Generates and Ascon 128 nonce.
   * @returns Uint8Array
   */
  
  ascon128Nonce(): Uint8Array {
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
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
  ): Uint8Array {
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
   * @returns Uint8Array
   */
  
  ascon128Decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array {
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
