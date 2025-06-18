import {
  CASAesKeyFromX25519SharedSecret,
  aes128Decrypt,
  aes128Encrypt,
  aes128Key,
  aes128KeyFromX25519SharedSecret,
  aes256Decrypt,
  aes256Encrypt,
  aes256Key,
  aes256KeyFromX25519SharedSecret,
  aesNonce,
} from "../../index";


export class AESWrapper {

    /**
     * @description Generates a 128 bit AES key
     * @returns returns a 128 bit AES key
     */
    public aes128Key(): Array<number> {
        return aes128Key();
    }

    /**
     * @description Generates a 256 bit AES key
     * @returns returns a 256 bit AES key
     */
    public aes256Key(): Array<number> {
        return aes256Key();
    }

    /**
     * Generates an 96 bit AES nonce
     * @returns Array<number>
     */
    public generateAESNonce(): Array<number> {
        return aesNonce();
    }

    /**
     * Encrypts with AES 128.
     * @param aesKey 
     * @param nonce 
     * @param plaintext 
     * @returns Array<number>
     */
    public aes128Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes128Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 128
     * @param aesKey 
     * @param nonce 
     * @param ciphertext 
     * @returns Array<number>
     */
    public aes128Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes128Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Encrypts with AES-256
     * @param aesKey 
     * @param nonce 
     * @param plaintext 
     * @returns 
     */
    public aes256Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes256Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 256
     * @param aesKey 
     * @param nonce 
     * @param ciphertext 
     * @returns 
     */
    public aes256Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes256Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Derives an AES-256 key from a X25519 Diffie Hellman shared secret.
     * @param shared_secret 
     * @returns 
     */
    public aes256KeyNonceX25519DiffieHellman(shared_secret: Array<number>): CASAesKeyFromX25519SharedSecret {
         return aes256KeyFromX25519SharedSecret(shared_secret);
    }

    /**
     * Derives an AES-128 key from a X25519 Diffie Hellman shared secret.
     * @param shared_secret 
     * @returns 
     */
    public aes128KeyNonceX25519DiffieHellman(shared_secret: Array<number>): CASAesKeyFromX25519SharedSecret {
        return aes128KeyFromX25519SharedSecret(shared_secret);
   }
}
