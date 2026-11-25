import {
  ascon128Decrypt,
  ascon128Encrypt,
  ascon128KeyGenerate,
  ascon128NonceGenerate,
  ascon128Open,
  ascon128Seal,
} from "../../index";


export class AsconWrapper {
  /**
   * Encrypts with Ascon-AEAD128 under a fresh random 128 bit nonce and returns
   * `nonce (16 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
   * nonce is generated for you, so it cannot be reused by mistake. The 128 bit nonce leaves a
   * far larger margin than the 96 bit nonces of AES-GCM and ChaCha20-Poly1305.
   * @param key 16 byte key from ascon128Key()
   * @param plaintext
   * @param aad optional additional authenticated data: not encrypted or stored in the
   * output, but the same bytes must be passed to ascon128Open. Omitting it is the same as empty AAD.
   * @returns Array<number>
   */

  ascon128Seal(key: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
    return ascon128Seal(key, plaintext, aad);
  }

  /**
   * Decrypts a `nonce || ciphertext || tag` blob produced by ascon128Seal.
   * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
   * shorter than nonce + tag (32 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
   * tag or AAD do not authenticate.
   * @param key the key passed to ascon128Seal
   * @param sealed output of ascon128Seal
   * @param aad the AAD passed to ascon128Seal, if any
   * @returns Array<number>
   */

  ascon128Open(key: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
    return ascon128Open(key, sealed, aad);
  }

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
   * Never reuse a nonce with the same key. Prefer ascon128Seal, which generates the nonce for you.
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
