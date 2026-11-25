import {
  aes128GcmSivDecrypt,
  aes128GcmSivEncrypt,
  aes128GcmSivKey,
  aes128GcmSivKeyFromVec,
  aes128GcmSivKeyFromX25519SharedSecret,
  aes128GcmSivOpen,
  aes128GcmSivSeal,
  aes256GcmSivDecrypt,
  aes256GcmSivEncrypt,
  aes256GcmSivKey,
  aes256GcmSivKeyFromVec,
  aes256GcmSivKeyFromX25519SharedSecret,
  aes256GcmSivOpen,
  aes256GcmSivSeal,
  aesGcmSivNonce,
} from "../../index";



export class AESGCMSIVWrapper {

    /**
     * Encrypts with AES-128-GCM-SIV under a fresh random 96 bit nonce and returns
     * `nonce (12 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
     * nonce is generated for you, so it cannot be reused by mistake.
     * Rotate keys well before about 2^32 messages per key.
     * @param aesKey 16 byte key from aes128Key()
     * @param plaintext
     * @param aad optional additional authenticated data: not encrypted or stored in the
     * output, but the same bytes must be passed to aes128Open. Omitting it is the same as empty AAD.
     * @returns Array<number>
     */

    public aes128Seal(aesKey: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
        return aes128GcmSivSeal(aesKey, plaintext, aad);
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob produced by aes128Seal.
     * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
     * shorter than nonce + tag (28 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
     * tag or AAD do not authenticate.
     * @param aesKey the key passed to aes128Seal
     * @param sealed output of aes128Seal
     * @param aad the AAD passed to aes128Seal, if any
     * @returns Array<number>
     */

    public aes128Open(aesKey: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
        return aes128GcmSivOpen(aesKey, sealed, aad);
    }

    /**
     * Encrypts with AES-256-GCM-SIV under a fresh random 96 bit nonce and returns
     * `nonce (12 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
     * nonce is generated for you, so it cannot be reused by mistake.
     * Rotate keys well before about 2^32 messages per key.
     * @param aesKey 32 byte key from aes256Key()
     * @param plaintext
     * @param aad optional additional authenticated data: not encrypted or stored in the
     * output, but the same bytes must be passed to aes256Open. Omitting it is the same as empty AAD.
     * @returns Array<number>
     */

    public aes256Seal(aesKey: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
        return aes256GcmSivSeal(aesKey, plaintext, aad);
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob produced by aes256Seal.
     * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
     * shorter than nonce + tag (28 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
     * tag or AAD do not authenticate.
     * @param aesKey the key passed to aes256Seal
     * @param sealed output of aes256Seal
     * @param aad the AAD passed to aes256Seal, if any
     * @returns Array<number>
     */

    public aes256Open(aesKey: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
        return aes256GcmSivOpen(aesKey, sealed, aad);
    }

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
     * Encrypts with AES-128-GCM-SIV (nonce-misuse-resistant AEAD) under a caller-supplied nonce.
     * The 128 bit tag is appended to the ciphertext. Use this when you have to manage nonces
     * yourself: reusing one only reveals whether two messages were identical. Otherwise prefer aes128Seal.
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
     * Encrypts with AES-256-GCM-SIV (nonce-misuse-resistant AEAD) under a caller-supplied nonce.
     * The 128 bit tag is appended to the ciphertext. Use this when you have to manage nonces
     * yourself: reusing one only reveals whether two messages were identical. Otherwise prefer aes256Seal.
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
     * Derives a 16 byte AES-128-GCM-SIV key from a X25519 Diffie Hellman shared secret with HKDF-SHA256.
     * The key is bound to AES-128-GCM-SIV and to both parties' public keys, so the same shared
     * secret gives unrelated keys for other ciphers, and both peers derive the same key only
     * if they saw the same public keys. Pass the public keys in either order.
     * Keys differ from those derived by earlier versions of this SDK: both peers must upgrade together.
     * Throws if any input is not 32 bytes or the shared secret is all zeros.
     * @param sharedSecret Output of X25519Wrapper.generateSharedSecret.
     * @param publicKeyA One party's 32 byte X25519 public key.
     * @param publicKeyB The other party's 32 byte X25519 public key.
     * @returns Array<number>
     */

    public aes128KeyFromX25519SharedSecret(sharedSecret: Array<number>, publicKeyA: Array<number>, publicKeyB: Array<number>): Array<number> {
        return aes128GcmSivKeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB);
    }

    /**
     * Derives a 32 byte AES-256-GCM-SIV key from a X25519 Diffie Hellman shared secret with HKDF-SHA256.
     * The key is bound to AES-256-GCM-SIV and to both parties' public keys, so the same shared
     * secret gives unrelated keys for other ciphers, and both peers derive the same key only
     * if they saw the same public keys. Pass the public keys in either order.
     * Keys differ from those derived by earlier versions of this SDK: both peers must upgrade together.
     * Throws if any input is not 32 bytes or the shared secret is all zeros.
     * @param sharedSecret Output of X25519Wrapper.generateSharedSecret.
     * @param publicKeyA One party's 32 byte X25519 public key.
     * @param publicKeyB The other party's 32 byte X25519 public key.
     * @returns Array<number>
     */

    public aes256KeyFromX25519SharedSecret(sharedSecret: Array<number>, publicKeyA: Array<number>, publicKeyB: Array<number>): Array<number> {
        return aes256GcmSivKeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB);
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
