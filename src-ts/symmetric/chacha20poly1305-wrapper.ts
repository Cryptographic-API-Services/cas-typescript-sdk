import {
  chacha20Poly1305Decrypt,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Key,
  chacha20Poly1305Nonce,
  chacha20Poly1305Open,
  chacha20Poly1305Seal,
} from "../../index";



export class ChaCha20Poly1305Wrapper {

    /**
     * Encrypts with ChaCha20-Poly1305 under a fresh random 96 bit nonce and returns
     * `nonce (12 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
     * nonce is generated for you, so it cannot be reused by mistake.
     * A random 96 bit nonce is only safe for about 2^32 messages per key, so rotate keys
     * well before that. If you have to manage nonces yourself, use AESGCMSIVWrapper,
     * which tolerates nonce reuse.
     * @param key 32 byte key from generateKey()
     * @param plaintext
     * @param aad optional additional authenticated data: not encrypted or stored in the
     * output, but the same bytes must be passed to open. Omitting it is the same as empty AAD.
     * @returns Array<number>
     */

    public seal(key: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
        return chacha20Poly1305Seal(key, plaintext, aad);
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob produced by seal.
     * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
     * shorter than nonce + tag (28 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
     * tag or AAD do not authenticate.
     * @param key the key passed to seal
     * @param sealed output of seal
     * @param aad the AAD passed to seal, if any
     * @returns Array<number>
     */

    public open(key: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
        return chacha20Poly1305Open(key, sealed, aad);
    }

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
     * Encrypts with ChaCha20-Poly1305 under a caller-supplied nonce. The 128 bit Poly1305 tag is
     * appended to the ciphertext. Never reuse a nonce with the same key: that reveals the XOR
     * of the plaintexts and lets an attacker forge messages. Prefer seal, which generates the nonce for you.
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
