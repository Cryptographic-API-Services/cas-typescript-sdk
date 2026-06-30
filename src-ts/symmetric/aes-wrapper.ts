import {
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

    public aes128Key(): Uint8Array {
        return aes128Key();
    }

    /**
     * @description Generates a 256 bit AES key
     * @returns returns a 256 bit AES key
     */

    public aes256Key(): Uint8Array {
        return aes256Key();
    }

    /**
     * Generates an 96 bit AES nonce
     * @returns Uint8Array
     */

    public generateAESNonce(): Uint8Array {
        return aesNonce();
    }

    /**
     * Encrypts with AES 128.
     * @param aesKey
     * @param nonce
     * @param plaintext
     * @returns Uint8Array
     */

    public aes128Encrypt(aesKey: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
        return aes128Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 128
     * @param aesKey
     * @param nonce
     * @param ciphertext
     * @returns Uint8Array
     */

    public aes128Decrypt(aesKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        return aes128Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Encrypts with AES-256
     * @param aesKey
     * @param nonce
     * @param plaintext
     * @returns
     */

    public aes256Encrypt(aesKey: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
        return aes256Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 256
     * @param aesKey
     * @param nonce
     * @param ciphertext
     * @returns
     */

    public aes256Decrypt(aesKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        return aes256Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Derives an AES-256 key from a X25519 Diffie Hellman shared secret.
     * @param shared_secret X25519 shared secret as a byte array (from the key_exchange domain)
     * @returns
     */

    public aes256KeyNonceX25519DiffieHellman(shared_secret: Uint8Array): Uint8Array {
         return aes256KeyFromX25519SharedSecret(shared_secret);
    }

    /**
     * Derives an AES-128 key from a X25519 Diffie Hellman shared secret.
     * @param shared_secret X25519 shared secret as a byte array (from the key_exchange domain)
     * @returns
     */

    public aes128KeyNonceX25519DiffieHellman(shared_secret: Uint8Array): Uint8Array {
        return aes128KeyFromX25519SharedSecret(shared_secret);
   }
}
