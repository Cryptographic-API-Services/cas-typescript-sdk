import {
  chacha20Poly1305Decrypt,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Key,
  chacha20Poly1305Nonce,
} from "../../index";



export class ChaCha20Poly1305Wrapper {

    /**
     * @description Generates a 256 bit ChaCha20-Poly1305 key
     * @returns returns a 256 bit ChaCha20-Poly1305 key
     */

    public generateKey(): Array<number> {
        return chacha20Poly1305Key();
    }

    /**
     * Generates a 96 bit ChaCha20-Poly1305 nonce
     * @returns Array<number>
     */

    public generateNonce(): Array<number> {
        return chacha20Poly1305Nonce();
    }

    /**
     * Encrypts with ChaCha20-Poly1305. The 128 bit Poly1305 tag is appended to the ciphertext.
     * @param key
     * @param nonce
     * @param plaintext
     * @returns Array<number>
     */

    public encrypt(key: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return chacha20Poly1305Encrypt(key, nonce, plaintext);
    }

    /**
     * Decrypts with ChaCha20-Poly1305. Expects the 128 bit Poly1305 tag appended to the ciphertext.
     * @param key
     * @param nonce
     * @param ciphertext
     * @returns Array<number>
     */

    public decrypt(key: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return chacha20Poly1305Decrypt(key, nonce, ciphertext);
    }
}
