import {
  AesKeyFromX25519SharedSecret,
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

/**
 * @description A wrapper class that contains methods to construct keys, nonces, and methods to encrypt and decrypt with AES-128-GCM and AES-256-GCM
 * 
 * @example
 * ```ts
 * const nonce = aesWrapper.generateAESNonce();
const key = aesWrapper.aes128Key();
const textEncoder = new TextEncoder();
const array = Array.from(textEncoder.encode("Hello World"));
const encrypted = aesWrapper.aes128Encrypt(key, nonce, array);
 * ```
 */
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

    public generateAESNonce(): Array<number> {
        return aesNonce();
    }

    public aes128Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes128Encrypt(aesKey, nonce, plaintext);
    }

    public aes128Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes128Decrypt(aesKey, nonce, ciphertext);
    }

    public aes256Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes256Encrypt(aesKey, nonce, plaintext);
    }

    public aes256Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes256Decrypt(aesKey, nonce, ciphertext);
    }

    public aes256KeyNonceX25519DiffieHellman(shared_secret: Array<number>): AesKeyFromX25519SharedSecret {
         return aes256KeyFromX25519SharedSecret(shared_secret);
    }

    public aes128KeyNonceX25519DiffieHellman(shared_secret: Array<number>): AesKeyFromX25519SharedSecret {
        return aes128KeyFromX25519SharedSecret(shared_secret);
   }
}
