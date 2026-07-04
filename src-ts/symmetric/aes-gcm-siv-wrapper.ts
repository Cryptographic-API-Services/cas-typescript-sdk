import {
  aes128GcmSivDecrypt,
  aes128GcmSivEncrypt,
  aes128GcmSivKey,
  aes128GcmSivKeyFromVec,
  aes128GcmSivKeyFromX25519SharedSecret,
  aes256GcmSivDecrypt,
  aes256GcmSivEncrypt,
  aes256GcmSivKey,
  aes256GcmSivKeyFromVec,
  aes256GcmSivKeyFromX25519SharedSecret,
  aesGcmSivNonce,
} from "../../index";



export class AESGCMSIVWrapper {

    /**
     * @description Generates a 128 bit AES-GCM-SIV key
     * @returns returns a 128 bit AES-GCM-SIV key
     */

    public aes128Key(): Array<number> {
        return aes128GcmSivKey();
    }

    /**
     * @description Generates a 256 bit AES-GCM-SIV key
     * @returns returns a 256 bit AES-GCM-SIV key
     */

    public aes256Key(): Array<number> {
        return aes256GcmSivKey();
    }

    /**
     * Generates a 96 bit AES-GCM-SIV nonce
     * @returns Array<number>
     */

    public generateNonce(): Array<number> {
        return aesGcmSivNonce();
    }

    /**
     * Encrypts with AES-128-GCM-SIV (nonce-misuse-resistant AEAD). The 128 bit tag is appended to the ciphertext.
     * @param aesKey
     * @param nonce
     * @param plaintext
     * @returns Array<number>
     */

    public aes128Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes128GcmSivEncrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES-128-GCM-SIV. Expects the 128 bit tag appended to the ciphertext.
     * @param aesKey
     * @param nonce
     * @param ciphertext
     * @returns Array<number>
     */

    public aes128Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes128GcmSivDecrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Encrypts with AES-256-GCM-SIV (nonce-misuse-resistant AEAD). The 128 bit tag is appended to the ciphertext.
     * @param aesKey
     * @param nonce
     * @param plaintext
     * @returns Array<number>
     */

    public aes256Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes256GcmSivEncrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES-256-GCM-SIV. Expects the 128 bit tag appended to the ciphertext.
     * @param aesKey
     * @param nonce
     * @param ciphertext
     * @returns Array<number>
     */

    public aes256Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes256GcmSivDecrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Derives an AES-128-GCM-SIV key from a X25519 Diffie Hellman shared secret.
     * @param sharedSecret
     * @returns Array<number>
     */

    public aes128KeyFromX25519SharedSecret(sharedSecret: Array<number>): Array<number> {
        return aes128GcmSivKeyFromX25519SharedSecret(sharedSecret);
    }

    /**
     * Derives an AES-256-GCM-SIV key from a X25519 Diffie Hellman shared secret.
     * @param sharedSecret
     * @returns Array<number>
     */

    public aes256KeyFromX25519SharedSecret(sharedSecret: Array<number>): Array<number> {
        return aes256GcmSivKeyFromX25519SharedSecret(sharedSecret);
    }

    /**
     * Validates a caller-supplied 16 byte key for AES-128-GCM-SIV. Throws if the length is wrong.
     * @param key
     * @returns Array<number>
     */

    public aes128KeyFromBytes(key: Array<number>): Array<number> {
        return aes128GcmSivKeyFromVec(key);
    }

    /**
     * Validates a caller-supplied 32 byte key for AES-256-GCM-SIV. Throws if the length is wrong.
     * @param key
     * @returns Array<number>
     */

    public aes256KeyFromBytes(key: Array<number>): Array<number> {
        return aes256GcmSivKeyFromVec(key);
    }
}
